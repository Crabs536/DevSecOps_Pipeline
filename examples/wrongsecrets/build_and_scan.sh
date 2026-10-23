#!/usr/bin/env bash
# Build an OWASP WrongSecrets application image from source, then scan it.
# Arguments: <checkout_dir> <image_tag> <trivy_report_json>
set -Eeuo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <checkout_dir> <image_tag> <trivy_report_json>" >&2
  exit 2
fi

CHECKOUT="$(realpath "$1")"
IMAGE_TAG="$2"
OUT="$(realpath -m "$3")"

[[ -f "$CHECKOUT/pom.xml" && -f "$CHECKOUT/Dockerfile" && -f "$CHECKOUT/mvnw" ]] || {
  echo "[ERROR] WrongSecrets checkout is incomplete: $CHECKOUT" >&2
  exit 3
}
mkdir -p "$(dirname "$OUT")"

# Derive Dockerfile's argBasedVersion from pom.xml; Dockerfile needs
# target/wrongsecrets-<argBasedVersion>-SNAPSHOT.jar to exist first.
VERSION="$(python3 - "$CHECKOUT/pom.xml" <<'PY'
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
ns = {'m': 'http://maven.apache.org/POM/4.0.0'}
value = root.findtext('m:version', namespaces=ns)
if not value or not value.endswith('-SNAPSHOT'):
    raise SystemExit('WrongSecrets Dockerfile requires project.version ending in -SNAPSHOT')
print(value[:-len('-SNAPSHOT')])
PY
)"

printf '[BUILD] Maven package from %s (version %s)\n' "$CHECKOUT" "$VERSION"
(
  cd "$CHECKOUT"
  bash ./mvnw -B -ntp -DskipTests package
)
JAR="$CHECKOUT/target/wrongsecrets-${VERSION}-SNAPSHOT.jar"
[[ -f "$JAR" ]] || { echo "[ERROR] Missing Maven output: $JAR" >&2; exit 4; }

# The upstream Dockerfile intentionally has RUN --mount=type=secret,id=mysecret.
# Supply a LAB-ONLY dummy value. Never provide secrets from CI to a PR build.
DUMMY_SECRET="$(mktemp)"
trap 'rm -f "$DUMMY_SECRET"' EXIT
printf '%s\n' 'devsecops-lab-placeholder-not-a-secret' > "$DUMMY_SECRET"

printf '[BUILD] Docker image %s\n' "$IMAGE_TAG"
(
  cd "$CHECKOUT"
  DOCKER_BUILDKIT=1 docker build \
    --platform linux/amd64 \
    --secret "id=mysecret,src=$DUMMY_SECRET" \
    --build-arg "argBasedVersion=$VERSION" \
    --build-arg 'argBasedPassword=devsecops-lab-placeholder' \
    -f Dockerfile -t "$IMAGE_TAG" .
)

printf '[SCAN] Trivy image %s -> %s\n' "$IMAGE_TAG" "$OUT"
trivy image --scanners vuln --format json --exit-code 0 \
  --timeout 15m --output "$OUT" "$IMAGE_TAG"
python3 - "$OUT" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
  v = json.load(f)
if not isinstance(v.get('SchemaVersion'), int) or not isinstance(v.get('Results'), list):
  raise SystemExit('[ERROR] Trivy JSON report is incomplete')
print('[OK] Trivy JSON verified')
PY
