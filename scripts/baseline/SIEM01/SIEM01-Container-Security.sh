systemctl is-active docker 2>/dev/null || echo "Docker not installed"   # check if Docker service is running
docker --version 2>/dev/null || echo "Docker CLI not available"         # check if Docker client is installed and version
docker ps 2>/dev/null || echo "No running containers"                   # list running containers if Docker is active