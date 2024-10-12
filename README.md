# yombar

A simpler, faster, and more lightweight implementation of [Cryptomator](https://github.com/cryptomator/cryptomator) using Rust.

## Usage

```
Usage: yombar [OPTIONS] <COMMAND>

Commands:
  create     Create a new empty vault
  mount      Mount a vault as a virtual filesystem
  translate  Translate between cleartext paths and encrypted paths
  help       Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose...
  -h, --help        Print help
  -V, --version     Print version
```

## Performance

Below are some rough performance comparisons between Cryptomator and `yombar` for common tasks.

Using: Cryptomator 1.14.0, `yombar` [393de15](https://github.com/0xSiO/yombar/tree/393de158e17b9cdff1b417525018234c992fb9d5)

OS: Linux 6.10.12

### Directory List / Search

I found `yombar` to be about **1.1x** faster on the first run, and about **10x** faster on subsequent runs.

<details>
<summary>Click for test details</summary>

Using: `fd` 10.1.0

Drive: Seagate 5TB Portable, ext4 filesystem

First, warm up caches for the underlying filesystem, allocate inodes, etc.
```sh
$ cd '/run/media/luc/Seagate 5TB'
$ fd > /dev/null
```

Start Cryptomator and mount vault.
```sh
$ cd /path/to/virtual/cryptomator/vault

$ time fd > /dev/null
fd > /dev/null  0.45s user 0.73s system 14% cpu 7.972 total

$ time fd > /dev/null
fd > /dev/null  0.53s user 0.85s system 15% cpu 8.908 total

$ fd | wc -l
13206
```

Unmount drive, mount again, and warm up underlying caches like before. Start `yombar` and mount vault.
```sh
$ cd /path/to/virtual/yombar/vault

$ time fd > /dev/null
fd > /dev/null  0.34s user 0.56s system 12% cpu 7.380 total

$ time fd > /dev/null
fd > /dev/null  0.15s user 0.24s system 44% cpu 0.880 total

$ fd | wc -l
13206
```

</details>

### Sequential Reads / Writes

I found `yombar` to be about **1.5x** faster for both sequential reads and sequential writes.

<details>
<summary>Click for test details</summary>

Drive: Samsung MZVL22T0HBLB 2TB, btrfs filesystem with LUKS2 encryption

Using a large video file:
```sh
$ du -h large_video_file.mkv
8.4G    large_video_file.mkv
```

Start Cryptomator and mount vault.
```sh
$ cd /path/to/virtual/cryptomator/vault

# Read
$ time /bin/cat large_video_file.mkv > /dev/null
/bin/cat large_video_file.mkv > /dev/null  0.05s user 4.23s system 40% cpu 10.637 total

# Write
$ time /bin/cat ~/original/large_video_file.mkv > ./large_video_file.mkv
/bin/cat ~/original/large_video_file.mkv > ./large_video_file.mkv  0.16s user 9.42s system 19% cpu 48.362 total
```

Start `yombar` and mount vault.
```sh
$ cd /path/to/virtual/yombar/vault

# Read
$ time /bin/cat ./large_video_file.mkv > /dev/null
/bin/cat ./large_video_file.mkv > /dev/null  0.02s user 1.71s system 24% cpu 6.932 total

# Write
$ time /bin/cat ~/original/large_video_file.mkv > ./large_video_file.mkv
/bin/cat ~/original/large_video_file.mkv > ./large_video_file.mkv  0.13s user 6.50s system 20% cpu 32.880 total
```

</details>

### Memory Usage

Snapshot from `top`, showing idle memory usage after unlocking vault:
```
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
 242954 luc       20   0 8130.1m 463.3m 116.7m S   0.0   1.5   0:17.44 Cryptomator
 242897 luc       20   0   24.8m   6.0m   5.1m S   0.0   0.0   0:00.31 yombar
```

And again, after populating the inode cache with `fd`:
```
    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
 242954 luc       20   0 9500.1m 532.0m 116.7m S   3.0   1.7   0:50.35 Cryptomator
 242897 luc       20   0   29.2m   9.2m   5.1m S   0.0   0.0   0:04.26 yombar
```

## Contributing

- Contributions to this project must be submitted under the [project's license](./LICENSE).
- Contributors to this project must attest to the [Developer Certificate of Origin](https://developercertificate.org/) by including a `Signed-off-by` statement in all commit messages.
- All commits must have a valid digital signature.
