# Seth on Docker (linux/arm64) — Mac (Apple Silicon)

These scripts mirror the flow of **`simple_remote.sh`** (package + deploy), **`temp_cmd.sh`** (unpack layout under `/root/seths/…`), and **`start_cmd.sh`** (start processes; sysctl is skipped in containers via `SETH_SKIP_SYSCTL`).

## Prerequisites

- Docker Desktop on Mac (Apple Silicon runs **linux/arm64** natively; enable Rosetta only if you force `linux/amd64`).
- Enough disk for build artifacts under `cbuild_Release/` or `cbuild_Debug/`.

## 1) Build binaries for Linux ARM64

From the **repository root**:

```bash
chmod +x docker/arm64/*.sh
bash docker/arm64/build_linux_arm64.sh Release
```

This runs `ubuntu:22.04` **linux/arm64**, installs toolchain deps, then `bash build.sh seth Release` and `make txcli` inside the container. Outputs go to `cbuild_Release/seth` and `cbuild_Release/txcli` on the host (bind-mounted).

If CMake fails (missing prebuilt third_party libs for aarch64), build on a Linux arm64 machine or CI and copy `cbuild_Release/seth` + `txcli` here.

## 2) Prepare `staging/pkg` (same as remote `/root/pkg`)

You need the same directory layout as after `make_package` on a deploy host:

- `seth`, `txcli`, `temp/`, `shards2`, `shards3`, `init_accounts*`, `shard_db_2`, `shard_db_3`, `GeoLite2-City.mmdb`, `log4cpp.properties`, …

**Option A — copy from an existing Linux deploy**

```bash
mkdir -p docker/arm64/staging
rsync -a user@host:/root/pkg/ docker/arm64/staging/pkg/
```

**Option B — use `pkg.tar.gz` from a deploy**

```bash
cp pkg.tar.gz docker/arm64/staging/pkg.tar.gz
USE_PKG_TAR=1 bash docker/arm64/simple_remote_docker.sh ...
```

(`USE_PKG_TAR=1` unpacks `staging/pkg.tar.gz` into `staging/pkg/` before run.)

**Option C — bundle already under `/root/pkg` (remote-style, or another path)**

If you run from a Linux environment where the deploy tree is already at **`/root/pkg`** (with `./seth` present) and you did **not** populate `docker/arm64/staging/pkg/`, the script will **automatically** use `/root/pkg` as the read-only mount source. To force only `staging/pkg` or an explicit path, set **`SETH_NO_ROOT_PKG_FALLBACK=1`** or **`SETH_PKG_DIR=/path/to/pkg`**.

```bash
export SETH_PKG_DIR=/data/my_pkg   # optional explicit bundle directory (must contain ./seth)
export SETH_STAGING=/tmp/seth-staging   # optional: where seths/ data is created (default under repo)
```

## 2.5) Already inside Ubuntu / no nested Docker

If your shell is **inside** a container (or any Linux host) that has **no** Docker daemon and you already have the repo plus a deploy bundle (`/root/pkg` or `SETH_PKG_DIR` / `staging/pkg`), run the same temp + start flow **without** `docker build` / `docker run`:

```bash
cd /path/to/SethPub   # repository root inside the container
chmod +x docker/arm64/*.sh simple_remote_in_container.sh 2>/dev/null || true
bash simple_remote_in_container.sh 10 172.17.0.2
# equivalent:
# bash docker/arm64/simple_remote_in_container.sh 10 172.17.0.2
```

This script symlinks `/root/pkg` to your resolved bundle when needed, runs `temp_cmd_docker.sh`, then `start_cmd_in_container.sh` (repo `start_cmd.sh` with `SETH_SKIP_SYSCTL=1`). Data ends up under **`/root/seths`** on that machine (not under `docker/arm64/staging/seths`).

## 3) Build runtime image and start nodes (one host)

```bash
export RUN_IMAGE=seth-node:arm64   # optional
bash docker/arm64/simple_remote_docker.sh \
  4 \
  host.docker.internal \
  3 \
  Release \
  4
```

Arguments (aligned with remote usage, without SSH/password):

1. `each_nodes_count` — nodes per shard on this “host” (passed to `start_cmd` as count).
2. `public_ip` — advertise this IP in configs (from Mac, peers often use your LAN IP or `host.docker.internal` for local clients).
3. `end_shard` — default `3`.
4. `Release` | `Debug` — must match `cbuild_*` used when building the `pkg` binaries.
5. Optional **first node count** for the first host (default = arg 1), same as `simple_remote.sh`’s `FIRST_NODE_COUNT`.

The script:

- Builds **`docker/arm64/Dockerfile.runtime`** (`seth-node:arm64`).
- Runs **`temp_cmd_docker.sh`** then **`start_cmd_docker.sh`** in one container with:
  - `/root/pkg` → resolved deploy bundle: `staging/pkg`, or `SETH_PKG_DIR`, or `/root/pkg` when present (see §2)
  - `/root/seths` → `docker/arm64/staging/seths` (read-write, persists data)

`start_cmd.sh` is bind-mounted so edits on the host apply without rebuilding the image (except when you change installed packages).

## 4) Publish ports

The template assigns ports like `12001`, `22001`, … inside the container. To reach them from macOS, add `-p` mappings or use **docker compose** with a `ports:` section. Example single-node HTTP:

```bash
docker run -d --platform linux/arm64 --name seth-a \
  -p 22001:22001 -p 12001:12001 -p 32001:32001 \
  -v "$(pwd)/docker/arm64/staging/pkg:/root/pkg:ro" \
  -v "$(pwd)/docker/arm64/staging/seths:/root/seths" \
  ... "${RUN_IMAGE}" bash -lc '...'
```

## Files

| File | Role |
|------|------|
| `docker/arm64/build_linux_arm64.sh` | Build `seth` + `txcli` in arm64 Ubuntu container |
| `docker/arm64/Dockerfile.runtime` | Small runtime image (openssl, iproute2, …) |
| `docker/arm64/temp_cmd_docker.sh` | Container-safe `temp_cmd` + fixed instance dir `s{shard}_{i}` |
| `docker/arm64/start_cmd_docker.sh` | Sets `SETH_SKIP_SYSCTL=1`, runs `/root/start_cmd.sh` (bind-mounted in `docker run`) |
| `docker/arm64/start_cmd_in_container.sh` | Same sysctl skip; runs repo `start_cmd.sh` by path (no Docker) |
| `docker/arm64/simple_remote_docker.sh` | One-shot on a Docker host: build image + `docker run` + temp + start |
| `docker/arm64/simple_remote_in_container.sh` | One-shot on the current OS: temp + start (no nested Docker) |
| `simple_remote_in_container.sh` (repo root) | Wrapper with the same argv mapping as `simple_remote_docker.sh` |

## `start_cmd.sh` change

TCP sysctl / `sysctl -p` are skipped when there is no write access to proc (typical Docker on Mac) or when `SETH_SKIP_SYSCTL=1`.
