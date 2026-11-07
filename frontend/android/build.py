"""Compila o aplicativo usando SDK local e uma credencial privada da instalação."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

android_dir = Path(__file__).resolve().parent
root = android_dir.parents[1]
sdk = Path(os.environ.get('ANDROID_SDK_ROOT', os.environ.get('ANDROID_HOME', '/nonexistent')))
bt = Path(os.environ.get('MIMO_BUILD_TOOLS', str(sdk / 'build-tools/35.0.0')))
android_jar = Path(os.environ.get('MIMO_ANDROID_JAR', str(sdk / 'platforms/android-35/android.jar')))
jsoup = Path(os.environ.get('JSOUP_JAR', '/nonexistent'))
token_path = Path(os.environ.get('MIMO_TOKEN_FILE', str(root / 'backend/token')))
for path in (android_jar, jsoup, token_path, bt / 'aapt2', bt / 'd8', bt / 'zipalign', bt / 'core-lambda-stubs.jar'):
    if not path.is_file():
        raise SystemExit(f'Dependência ausente: {path}. Consulte docs/INSTALACAO.md.')
token = token_path.read_text().strip()
if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', token):
    raise SystemExit('Formato de credencial inválido. Use scripts/init_local.py.')
build = root / 'build/android'
if build.exists():
    shutil.rmtree(build)
source = build / 'src/local/poco/ai'
source.mkdir(parents=True)
for file in (android_dir / 'src/local/poco/ai').glob('*.java'):
    if file.name != 'WebConfig.java':
        shutil.copy2(file, source / file.name)
config = source / 'WebConfig.java'
config.write_text('package local.poco.ai; final class WebConfig { static final String TOKEN = ' + json.dumps(token) + '; }\n')
config.chmod(0o600)
classes = build / 'classes'
dex = build / 'dex'
classes.mkdir()
dex.mkdir()
def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)
run('java', '-m', 'jdk.compiler/com.sun.tools.javac.Main', '-source', '8', '-target', '8',
    '-bootclasspath', str(android_jar) + os.pathsep + str(bt / 'core-lambda-stubs.jar'),
    '-classpath', jsoup, '-d', classes, *sorted(source.glob('*.java')))
run(bt / 'd8', '--lib', android_jar, '--min-api', '26', '--output', dex, jsoup, *sorted(classes.rglob('*.class')))
resources = build / 'resources.zip'
run(bt / 'aapt2', 'compile', '--dir', android_dir / 'res', '-o', resources)
raw = build / 'base.apk'
run(bt / 'aapt2', 'link', '-o', raw, '-I', android_jar, '--manifest', android_dir / 'AndroidManifest.xml', resources)
with zipfile.ZipFile(raw, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
    for file in sorted(dex.glob('*.dex')):
        archive.write(file, file.name)
    for name in ('index.html', 'app.js', 'styles.css', 'assets/cyber-mimo.png'):
        archive.write(android_dir.parent / 'dist' / name, 'assets/app/' + name)
output = build / 'POCO-Mimo-unsigned.apk'
run(bt / 'zipalign', '-f', '4', raw, output)
if os.environ.get('MIMO_KEYSTORE'):
    if not os.environ.get('MIMO_KEYSTORE_PASSWORD') or not os.environ.get('MIMO_KEY_ALIAS'):
        raise SystemExit('Defina MIMO_KEYSTORE_PASSWORD e MIMO_KEY_ALIAS para assinar.')
    signed = build / 'POCO-Mimo.apk'
    run(bt / 'apksigner', 'sign', '--ks', os.environ['MIMO_KEYSTORE'], '--ks-pass',
        'env:MIMO_KEYSTORE_PASSWORD', '--ks-key-alias', os.environ['MIMO_KEY_ALIAS'], '--out', signed, output)
    run(bt / 'apksigner', 'verify', signed)
    output = signed
print('APK privado gerado:', output)
print('A credencial está embutida no APK. Não publique este arquivo.')
