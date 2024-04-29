# mrpack-container

A command line utility that turns a Modrinth `.mrpack` file into a ready-to-use container image.

`mrpack-container` is:
- Fast
- Lightweight
- Has minimal dependencies
- Pure Rust
- Does not require a JVM
- Does not require a container runtime
- Deterministic, produces the same output each time (-ish) 
- Direct streaming: no temporary files or scratch space required

The resulting containers are:
- Small, usually a few hundred MB depending on mods installed
- Fast to start up, with no downloads on bootup required
- Security focused, running as non-root with the majority of the filesystem immutable
- Immutable, with (almost) all dependencies packaged they will not change over time  

The only missing dependency is the Mojang server.jar itself, which is non-redistributable.
You can either add another container layer ontop of one generated here, or you can download it and mount it in at runtime.
Generally speaking, you should place it at `/var/minecraft/server.jar` inside the container.

## Warnings

You are responsible for adhering to the licensing requirements of the mod files involved.
This project is not affiliated with Modrinth.
NOT AN OFFICIAL MINECRAFT PRODUCT. NOT APPROVED BY OR ASSOCIATED WITH MOJANG OR MICROSOFT.

**This is pre-Alpha and is under construction.**
In particular, the code quality is awful because this is thrown together.
Many things are not yet supported. For example, only Quilt works at the moment.

## Installing

Right now you will need to clone this repository with git, and then build the mrpack-container binary with Rust.
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
mrpack-container my-modpack.mrpack ./output --accept-eula
```

The output is in OCI format in the given directory, but not compressed. You can use `tar` to compress it into a single file: `tar cf - -C ./output .`.

You can load and execute the produced image directly with a container runtime.
```bash
tar cf - -C ./output/ . | podman load
```

## Using Images

You will need to mount:
- A Minecraft server var, usually at `/var/minecraft/sever.jar`
- If the eula wasn't accepted at build time, then you'll need to do it now by mounting in a text file containing `eula=true` to `/var/minecraft/eula.txt`.

And you will probably **want** to mount:
- A settings file, usually at `/var/minecraft/server.properties`
- A directory to store the world saves, usually at `/var/minecraft/world`

For example:
```bash
wget https://piston-data.mojang.com/v1/objects/84194a2f286ef7c14ed7ce0090dba59902951553/server.jar
mkdir world
podman run \
  -p 25565:25565 \
  -v "$(pwd)"/world:/var/minecraft/world \
  -v "$(pwd)"/server.jar:/var/minecraft/server.jar:ro \
  <container_id>
```

## Container Structure

- `/bin` with a simlink for `/bin/java` (to `/usr/local/java/bin/java`)
- `/lib` with the musl libc library
- `/usr/local/java` with the JVM
- `/usr/local/minecraft/lib` with modloader libraries
- `/usr/share/doc/musl` with copyright information for MUSL
- `/var/minecraft/eula.txt` if you passed `--accept-eula`

The files and overrides in the Modrinth file are unpacked into `/var/minecraft`.
Permissions are set as `0755` or `0644`, and most files are owned by root.
The container is intended to be run with the main process running as uid `1000` and gid `1000`, therefore a number of directories are owned by that user instead:
- `/var/minecraft`
- `/var/minecraft/config`
- `/var/miencraft/libraries`

This is an intentional security choice, in order to make an attacker with remote code execution on your Minecraft server have as hard of a job as possible mantaining persistence.

## Layers

The container makes extensive use of layering:

- A base layer, of musl from Debian. Including only the shared library and copyright information.
- a JRE
- Your mod loader of choice
- Each download from the mrpack file, one layer per download 
- overrides
- server overrides
- Minecraft `eula.txt` (if `--accept-eula` is passed) and permissions changes
