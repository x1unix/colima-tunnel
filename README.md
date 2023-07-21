# Colima Tunnel

Connect to Colima Docker containers directly by IP.

## Features

* **L3 connectivity:** Connect to Docker containers from macOS host (without port binding).
* **Lightweight:** Based on built-in Colima SSH server. No Wireguard or other sidecar containers required.
* **Automatic**: Docker networks are automatically added/removed from macOS routing table.

## Requirements

You must be using latest [colima](https://github.com/abiosoft/colima/).

If you're looking for a similar tool for Docker Desktop, please consider [docker-mac-net-connect](https://github.com/chipmk/docker-mac-net-connect).

## Architecture

This solution relies on Colima VM's built-in SSH server to access Docker containers.

Under the hood, this tool creates a virtual network tunnel on host side and establishes
SSH connection to Colima VM.

To establish connection to a container, it creates an SSH tunnel on demand and proxies
all networks requests to individual container directly via tunnel.

Basically it works as a virtual router between your mac and Colima VM's network.

