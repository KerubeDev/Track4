import argparse,os,random,sys
from app.emulator import parser
from app.emulator.attacks import build_attack_stream
from app.emulator.emitter import JsonLinesEmitter,KafkaBufferError,KafkaEmitter,NullEmitter
from app.emulator.mapping import ZoneMapping,DEFAULT_MAPPING_PATH
from app.emulator.playback import Playback,synthesize_stream,merge_event_streams
from app.emulator.replay import DEFAULT_RATE,DEFAULT_SEED,ReplayConfig,find_dataset_files,merged_stream
from app.emulator.synthesizer import DnstapSynthesizer
EMITTERS=("null","json","kafka")
def _env_float(n,d):return float(os.environ[n]) if n in os.environ else d
def _seed_default():return int(os.environ.get("DEMO_SEED") or os.environ.get("EMULATOR_SEED") or DEFAULT_SEED)
def parse_args(argv=None):
 p=argparse.ArgumentParser(prog="shield-emulator",description="Replay BIND9 queries, synthesize response telemetry, optionally inject labeled evaluation traffic, and emit normalized events.");p.add_argument("--dataset",default=os.environ.get("EMULATOR_DATASET",""));p.add_argument("--mapping",default=os.environ.get("ZONE_MAPPING",DEFAULT_MAPPING_PATH));p.add_argument("--rate",type=float,default=_env_float("REPLAY_RATE",DEFAULT_RATE));p.add_argument("--seed",type=int,default=_seed_default());p.add_argument("--attack",action="store_true");p.add_argument("--emit",choices=EMITTERS,default=os.environ.get("EMULATOR_EMIT","null"));p.add_argument("--out",default=None);p.add_argument("--bootstrap",default=os.environ.get("KAFKA_BOOTSTRAP","localhost:9092"));p.add_argument("--limit",type=int,default=0,help="maximum total emitted events after background/evaluation streams are merged (0=all)");p.add_argument("--partitions",type=int,default=3);return p.parse_args(argv)
def _logical_window(dataset):
 first=last=None
 for r in merged_stream(find_dataset_files(dataset)):
  if first is None:first=r.timestamp
  last=r.timestamp
 return first,last
def build_emitter(a):
 if a.emit=="json":return JsonLinesEmitter(sys.stdout if a.out is None else open(a.out,"w",encoding="utf-8"))
 if a.emit=="kafka":return KafkaEmitter(a.bootstrap,partitions=a.partitions)
 return NullEmitter()
def _limited(stream,limit):
 if limit<=0:yield from stream;return
 for i,e in enumerate(stream):
  if i>=limit:return
  yield e
def run(argv=None):
 a=parse_args(argv);mapping=ZoneMapping.from_csv(a.mapping);synth=DnstapSynthesizer(random.Random(a.seed));background=synthesize_stream(merged_stream(find_dataset_files(a.dataset)),mapping,synth) if a.dataset else iter(());attack=None
 if a.attack and a.dataset:attack=build_attack_stream(synth,mapping,_logical_window(a.dataset),random.Random(a.seed))
 stream=merge_event_streams(background,attack) if attack is not None else background;emitter=build_emitter(a);playback=Playback(ReplayConfig(replay_rate=a.rate,seed=a.seed))
 try:stats=playback.run(_limited(stream,a.limit),emitter)
 except KafkaBufferError as exc:print(f"FATAL: {exc}",file=sys.stderr);raise SystemExit(1)
 emitter.close();failed=f" kafka_failed={emitter.failed}" if a.emit=="kafka" and hasattr(emitter,"failed") else "";print(f"replayed={stats.events} attack={stats.attack_events} window=({stats.first_ts} .. {stats.last_ts}) rate=x{a.rate if a.rate>0 else 'no-wait'} seed={a.seed} emit={a.emit} decode_errs={parser.bad_decodes}{failed}");return stats
if __name__=="__main__":run()
