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

Using: Cryptomator 1.14.0, `yombar` [fc26e0d](https://github.com/0xSiO/yombar/tree/fc26e0dc1f7d0c5b9814260d91d0911d3f14db01)

OS: Linux 6.10.12

### Directory List / Search

I found `yombar` to be about **1.3x** faster on the first run, and about **9.6x** faster on subsequent runs.

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

$ time fd | wc -l
13206
fd  0.57s user 0.88s system 14% cpu 9.772 total
wc -l  0.01s user 0.05s system 0% cpu 9.772 total

$ time fd | wc -l
13206
fd  0.51s user 0.66s system 13% cpu 8.666 total
wc -l  0.00s user 0.04s system 0% cpu 8.665 total
```

Unmount drive, mount again, and warm up underlying caches like before. Start `yombar` and mount vault.
```sh
$ cd /path/to/virtual/yombar/vault

$ time fd | wc -l
13206
fd  0.39s user 0.61s system 13% cpu 7.258 total
wc -l  0.01s user 0.04s system 0% cpu 7.257 total

$ time fd | wc -l
13206
fd  0.15s user 0.23s system 41% cpu 0.902 total
wc -l  0.00s user 0.01s system 1% cpu 0.901 total
```

</details>

### Sequential Reads / Writes

I found `yombar` to be about **1.4x** faster for sequential reads, and about **1.9x** faster for sequential writes.

<details>
<summary>Click for test details</summary>

Drive: Samsung MZVL22T0HBLB 2TB, btrfs filesystem with LUKS2 encryption

Start Cryptomator and mount vault.
```sh
$ cd /path/to/virtual/cryptomator/vault

# Read
$ time /bin/cat large_video_file.mkv | pv > /dev/null
7.54GiB 0:00:11 [ 700MiB/s] [                         <=>                 ]
/bin/cat large_video_file.mkv  0.05s user 5.41s system 49% cpu 11.026 total
pv > /dev/null  0.14s user 1.59s system 15% cpu 11.025 total

# Write
$ rm large_video_file.mkv
$ time /bin/cat /path/to/original/large_video_file.mkv | pv > ./large_video_file.mkv
7.54GiB 0:01:13 [ 104MiB/s] [                                   <=>       ]
/bin/cat /path/to/original/large_video_file.mkv  0.16s user 8.68s system 11% cpu 1:13.83 total
pv > ./large_video_file.mkv  0.36s user 9.86s system 13% cpu 1:13.82 total
```

Start `yombar` and mount vault.
```sh
$ cd /path/to/virtual/yombar/vault

# Read
time /bin/cat large_video_file.mkv | pv > /dev/null
7.54GiB 0:00:08 [ 956MiB/s] [                   <=>                      ]
/bin/cat large_video_file.mkv  0.02s user 3.01s system 37% cpu 8.074 total
pv > /dev/null  0.04s user 0.60s system 7% cpu 8.074 total

# Write
$ rm large_video_file.mkv
$ time /bin/cat /path/to/original/large_video_file.mkv | pv > ./large_video_file.mkv
7.54GiB 0:00:39 [ 194MiB/s] [                      <=>                   ]
/bin/cat /path/to/original/large_video_file.mkv  0.10s user 5.25s system 13% cpu 39.631 total
pv > ./large_video_file.mkv  0.25s user 6.88s system 17% cpu 39.630 total
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
