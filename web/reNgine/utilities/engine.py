import os
from celery.utils.log import get_task_logger
from scanEngine.models import EngineType

logger = get_task_logger(__name__)


#------------------#
# EngineType utils #
#------------------#

def dump_custom_scan_engines(results_dir):
    """Dump custom scan engines to YAML files.

    Args:
        results_dir (str): Results directory (will be created if non-existent).
    """
    custom_engines = EngineType.objects.filter(default_engine=False)
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    for engine in custom_engines:
        with open(f'{results_dir}/{engine.engine_name}.yaml', 'w') as f:
            f.write(engine.yaml_configuration)


def load_custom_scan_engines(results_dir):
    """Load custom scan engines from YAML files. The filename without .yaml will
    be used as the engine name.

    Args:
        results_dir (str): Results directory containing engines configs.
    """
    config_paths = [
        f for f in os.listdir(results_dir)
        if os.path.isfile(os.path.join(results_dir, f)) and f.endswith('.yaml')
    ]
    for path in config_paths:
        engine_name = os.path.splitext(os.path.basename(path))[0]
        full_path = os.path.join(results_dir, path)
        with open(full_path, 'r') as f:
            yaml_configuration = f.read()

        engine, _ = EngineType.objects.get_or_create(engine_name=engine_name)
        engine.yaml_configuration = yaml_configuration
        engine.save() 