# 🕳Cavern🕳
The Cavern project aims to build an operating system, mostly for entertainment.
The name "Cavern" is inspired by [hobby tunneling](https://en.wikipedia.org/wiki/Hobby_tunneling), in which people dig tunnels for no reason but the pure enjoyment of digging.
Like digging a tunnel, building an OS is hard work with lots of stressful decisions and trade-offs, but with the right mindset it can be enjoyable for the committed.
This project builds on my previous efforts in the [k project](https://github.com/andrew-pa/k).

Cavern follows a microkernel architecture, using message passing and kernel-managed direct memory transfers to communicate between processes. Check out the specification [for the system](./spec/README.md) and [for the kernel](./spec/kernel.md) for more details.

Here's what it currently looks like to boot (slowed down significantly for readability, click for original):
[![Video of Cavern Booting Up](./boot-video.gif)](https://asciinema.org/a/eJNT7R5vkbvUNxQVC0i6kgUiY)
