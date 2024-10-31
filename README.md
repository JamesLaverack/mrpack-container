# mrpack-container

[![End to End Test](https://github.com/JamesLaverack/mrpack-container/actions/workflows/e2e.yaml/badge.svg?branch=main)](https://github.com/JamesLaverack/mrpack-container/actions/workflows/e2e.yaml)
[![Lint](https://github.com/JamesLaverack/mrpack-container/actions/workflows/lint.yaml/badge.svg?branch=main)](https://github.com/JamesLaverack/mrpack-container/actions/workflows/lint.yaml)
[![Rust Report Card](https://rust-reportcard.xuri.me/badge/github.com/jameslaverack/mrpack-container)](https://rust-reportcard.xuri.me/report/github.com/jameslaverack/mrpack-container)

Turn Modrinth modpack (`.mrpack`) files directly into ready-to-use container images.

- Fast to run (~10–20 seconds)
- No JVM needed
- No container runtime (Docker, Podman, etc.) needed
  
The resulting containers are:
- Small, usually a few hundred MB depending on mods installed
- Fast to start up, with no downloads on bootup required
- Security focused, running as non-root with the majority of the filesystem immutable
- Multi-architecture (AMD64 and ARM64) by default.

## Warnings

You are responsible for adhering to the licensing requirements of the mod files involved.
This project is not affiliated with Modrinth.
NOT AN OFFICIAL MINECRAFT PRODUCT. NOT APPROVED BY OR ASSOCIATED WITH MOJANG OR MICROSOFT.

## Installing

You will need to clone this repository with git, and then build the mrpack-container binary with Rust.
You will need to have a [Rust toolchain](https://www.rust-lang.org/tools/install) installed for your platform.

For example:
```bash
git clone https://github.com/JamesLaverack/mrpack-container.git
cd mrpack-container
cargo build --release
```

Or, from inside the `mrpack-container` directory, you can directly build and execute using `cargo run`. 

## Building Images

You need a Modrinth format modpack file (i.e., a `.mrpack` file).
You can find these on [Modrinth](https://modrinth.com/modpacks), or use [packwiz](https://packwiz.infra.link/) to convert other formats of modpack to the Modrinth format.

```bash
mrpack-container --arch amd64 --output ./output my-modpack.mrpack
```

The output is in OCI format in the given output directory, but not compressed. You can use `tar` to compress it into a single file: `tar cf - -C ./output .`.

You can load and execute the produced image directly with a container runtime.
```bash
tar cf - -C ./output/ . | podman load
```

or use [Skopeo](https://github.com/containers/skopeo) to upload it directly to a container runtime:
```bash
skopeo copy --format=oci oci:./output docker://registry.example.com/my-modpack:latest
```

## Multi-Architecture Images

By default, `mrpack-container` builds native multi-architecture images for both amd64 and arm64 platforms.
You can customise this behaviour with the `--arches`/`--arch` flag, as in the above examples.
Some tools do not work correctly with multi-architecture images.
In this case, you will need to either generate an image just for one architecture, or 'split' the image into one per architecture.
The different images in a multi-image archive will be named `$version-$arch`, using the provided pack version number.
For example, if the modpack `my-modpack.mrpack` is at version 1.2.3:

```bash
mrpack-container --arches amd64 --arhces arm64 --output ./output my-modpack.mrpack
skopeo copy oci:output:1.2.3-arm64 oci-archive:arm64.tar
skopeo copy oci:output:1.2.3-amd64 oci-archive:amd64.tar
```

When building a multi-architecture image, `mrpack-container` will output the container image names in the log output.

You can also view the image names in the `index.json` file in the output directory.
For example:

```bash
jq <output/index.json '.manifests[] | {arch: .platform.architecture, name: .annotations."org.opencontainers.image.ref.name"}'
```

## Using Images

You will need to provide and mount into the running container:
- A Minecraft server JAR from Mojang, of the correct Minecraft version for your mods and loader, usually mounted at `/usr/lib/minecraft/sever.jar`
- A file to accept the Minecraft [EULA](https://www.minecraft.net/en-us/eula), usually a text file containing `eula=true` at `/var/minecraft/eula.txt`.

And you will probably **want** to mount:
- A settings file, usually at `/var/minecraft/server.properties`
- A directory to store the world saves, usually at `/var/minecraft/world`

For example:
```bash
# Minecraft 1.20.1
wget https://piston-data.mojang.com/v1/objects/84194a2f286ef7c14ed7ce0090dba59902951553/server.jar
# Doing this means you are accepting the Minecraft EULA
echo "eula=true" > eula.txt
mkdir world
podman run \
  -p 25565:25565 \
  -v "$(pwd)"/world:/var/minecraft/world \
  -v "$(pwd)"/server.jar:/usr/lib/minecraft/server.jar:ro \
  -v "$(pwd)"/eula.txt:/var/minecraft/eula.txt:ro \
  <image_id>
```
Will run the server and make it available on `localhost:25565`.

## Container Structure

In general:
- `/bin`, `/lib`, and `/usr/` are used for system-level dependencies, i.e., Java.
- `/usr/local/minecraft` is used for immutable files to do with the Minecraft install.
- `/var/minecraft` is used for things that are mostly expected to be mutable at runtime.

In detail:
- `/bin` with a simlink for `/bin/java` (to `/usr/local/java/bin/java`)
- `/lib` with the glibc library
- `/usr/local/java` with the JVM
- `/usr/local/minecraft/lib` with modloader libraries

The files and overrides in the Modrinth file are unpacked into `/var/minecraft`.
Permissions are set as `0755` or `0644`, and most files are owned by root.
Some files, depending on their name, are set as `0777` or `0666` instead, allowing the Minecraft process to write to them.

The container is intended to be run with the main process running as uid `1000` and gid `1000`, therefore a number of directories are owned by that user instead:
- `/var/minecraft`
- `/var/minecraft/config`
- `/var/miencraft/libraries`

## Layers

The container makes extensive use of layering:

- Glibc from Debian.
- a JRE
- Your mod loader of choice
- Each download from the mrpack file, one layer per download 
- Overrides from the mrpack file
- Server overrides from the mrpack file
- Permissions changes

## Development

This project is written in pure [Rust](https://www.rust-lang.org/), and uses [Cargo](https://doc.rust-lang.org/cargo/) for all building.
[Tokio](https://tokio.rs/) is used as the async runtime of choice. 
