#!/usr/bin/env bash
# Deploy this Function App via zip-deploy with pre-built dependencies.
#
# SCM_DO_BUILD_DURING_DEPLOYMENT (remote Oryx build) is NOT reliable on this
# app — Kudu/SCM was found to be unreachable on this Linux Consumption plan
# during initial bring-up (all /api/* endpoints 404, even /api/environment),
# so the remote pip-install step silently never ran and the Python worker
# crash-looped on import with zero functions indexed. Bundling dependencies
# directly into the zip (the officially supported .python_packages
# mechanism) sidesteps the whole remote-build path.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="${FUNCTION_APP_NAME:-jarvis-provisioning-func}"
RESOURCE_GROUP="${RESOURCE_GROUP:-rg-jarvis-iot-bringup}"
PYTHON_VERSION="${PYTHON_VERSION:-$(python -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')}"

rm -rf .python_packages
pip install --target=".python_packages/lib/site-packages" -r requirements.txt \
  --only-binary=:all: --python-version "$PYTHON_VERSION" --platform manylinux2014_x86_64 --implementation cp

rm -f /tmp/provisioning-function-dist.zip
zip -rq /tmp/provisioning-function-dist.zip . -x "local.settings.json" -x ".gitignore" -x "deploy.sh"

az functionapp deployment source config-zip --name "$APP_NAME" \
  --resource-group "$RESOURCE_GROUP" --src /tmp/provisioning-function-dist.zip --timeout 600

rm -rf .python_packages /tmp/provisioning-function-dist.zip

echo "Deployed. Test with:"
echo "  curl -X POST \"https://${APP_NAME}.azurewebsites.net/api/v1/provision?code=<function-key>\" ..."
