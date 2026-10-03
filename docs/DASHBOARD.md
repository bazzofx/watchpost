
# Deploy SIEM
A simplify instructions to deploy the dashboard


```bash
export SIEM_ADMIN_PASSWORD='SamplePassword123!'      # optional; otherwise generated
export SIEM_ANALYST_PASSWORD='SamplePassword123!'     # optional; otherwise generated
export SIEM_VIEWER_PASSWORD='SamplePassword123!'     # optional; creates a read-only 
export SIEM_HOST=0.0.0.0

cd ~/apps/watchpost
./start.sh
```
