To use this demo, you will require an STM32F407-discovery board (or two for the remote attack)
and a USB-TTL adapter (we used one with an FTDI FT232 chipset).
Our code is based on https://github.com/mupq/pqm4 and we recommend to make sure to follow the getting started steps documented there first.

Required software:
 - st-link (https://github.com/stlink-org/stlink)
 - arm-none-eabi-gcc (https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
 - Python3 (and the packages installed below)
 - libopencm3 (https://github.com/libopencm3/libopencm3; see instructions below)

We rely on the libopencm3 library (We used version bb4c5d7324554fe7a3137bfbcf3b5200ee2648fa) in the m4 directory:

```
cd m4
git clone https://github.com/libopencm3/libopencm3
cd libopencm3 
git checkout bb4c5d7324554fe7a3137bfbcf3b5200ee2648fa
make
cd ../..
```

Additionally, we will require some Python3 packages (see requirements.txt).
Preferably, you should install those in a virtual environment:
```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```


Afterwards, you should be able to run the attack script assuming you have the board and USB-TTL adapter plugged in.
To reproduce the experiments in the paper, you can run:
```
# local attack (demo2a)
./m4.py -i 1 -n 2
# remote attack (demo2b)
./m4.py -i 4 -n 2 -r
```

If you are using cheap USB-TTL adapter, you will likely have to lower the baudrate in `m4.py`, 
`m4/hal-opencm3.c`, and `m4remote/attacker/hal-opencm3.c`.