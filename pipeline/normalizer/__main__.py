"""
Normalizer entrypoint — run with: python -m pipeline.normalizer.worker
"""
import yaml
from pipeline.normalizer.worker import NormalizerWorker

if __name__ == "__main__":
    with open("config.yaml") as f:
        cfg = yaml.safe_load(f)

    worker = NormalizerWorker(
        kafka_bootstrap=cfg["kafka"]["bootstrap_servers"],
        topics_config=cfg["kafka"]["topics"],
    )
    worker.start()
