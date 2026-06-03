FROM mcr.microsoft.com/dotnet/sdk:10.0

# Install additional tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    make \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*
