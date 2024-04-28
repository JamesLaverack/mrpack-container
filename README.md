# mrpack-container

A command line application that turns a Modrinth `.mrpack` file into ready-to-use container images.

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
- Immutable, with all dependencies packaged they will not change over time  

## Warnings

**This is pre-Alpha and is under construction.**
In particular, the code quality is awful because this is thrown together.
Many things are not yet supported. For example, only Quilt works at the moment.

You are responsible for adhering to the licensing requirements of the mod files involved.
This project is not affiliated with Modrinth.
NOT AN OFFICIAL MINECRAFT PRODUCT. NOT APPROVED BY OR ASSOCIATED WITH MOJANG OR MICROSOFT.

## 🚨**DO NOT DISTRIBUTE CONTAINER IMAGES MADE WITH THIS TOOL**🚨

Container images produced by this tool will contain Mojang property in the form of a minecraft `server.jar`.
The Minecraft EULA prohibits redistribution of their game code, including a `server.jar`.
**Only** use this tool locally, and load the resulting image directly into your container runtime or host in a **private** container registry.

## Building Images

You need a Modrinth format modpack file (i.e., a `.mrpack` file).
You can find these on [Modrinth](https://modrinth.com/modpacks), or use [packwiz](https://packwiz.infra.link/) to convert other formats of modpack to the Modrinth format.

```
mkdir ./output
mrpack-container my-modpack.mrpack ./output --accept-eula
```

You can load and execute the produced image directly:
```
tar cf - -C ./output/ . | podman load
podman run -p 25565:25565 <container_hash>
```

To **actually use** the container you'll probably want to mount in a directory over `/var/minecraft/world`. 
Plus a settings file as `/var/minecraft/server.properties`.

## Container Structure

- `/bin` with a simlink for `/bin/java` (to `/usr/local/java/bin/java`)
- `/lib` with the musl libc library
- `/usr/local/java` with the JVM
- `/usr/local/minecraft/lib` with modloader libraries
- `/usr/share/doc/musl` with copyright information for MUSL
- `/var/minecraft/eula.txt` with the result of passing `--accept-eula` or not
- `/var/minecraft/server.jar` with the Mojang Minecraft server JAR

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
- Minecraft `server.jar`, `eula.txt`, and permissions changes
