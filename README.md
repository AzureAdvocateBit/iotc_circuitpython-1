# Azure IoT Central CircuitPython library

This library is a CircuitPython implementation of a third party Azure IoT Central SDK.

The original implementation for Python and Micropython is here: [github.com/obastemur/iot_client](https://github.com/obastemur/iot_client)

## Supported boards

You will need an Adafruit board with WiFi connectivity via an ESP32 chip, either on-board or using a separate board. This has been tested using:

* [Adafruit PyPortal](https://www.adafruit.com/product/4116)
* [AdaFruit PyBadge](https://www.adafruit.com/product/4200) with an [Airlift FeatherWing](https://www.adafruit.com/product/4264)

## Usage

* Create an Azure IoT Central application, with a device template and a device. You can learn how to do this in the [Azure IoT Central docs](https://docs.microsoft.com/azure/iot-central/core/quick-deploy-iot-central/?WT.mc_id=academic-0000-jabenn). This application will need:

  * A device template with an interface containing:

    * A telemetry value called `value`

    * A Command called `command`

  * A view for the device showing the value of `value` as well as a way to run the command

  * A single device using this template

* Download the latest version of the Adafruit CircuitPython libraries from the [releases page](https://github.com/adafruit/Adafruit_CircuitPython_Bundle/releases)

* Copy the following to the `lib` folder on your CircuitPython device

    | Name                  | Type   |
    | --------------------- | ------ |
    | neopixel.mpy          | File   |
    | adafruit_minimqtt.mpy | File   |
    | adafruit_logging.mpy  | File   |
    | adafruit_binascii.mpy | File   |
    | adafruit_requests.mpy | File   |
    | adafruit_ntp.mpy      | File   |
    | adafruit_hashlib      | Folder |
    | adafruit_esp32spi     | Folder |
    | adafruit_bus_device   | Folder |

* Copy the code from this repo to the device

* Edit 'secrets.py` to include your WiFi SSID and password, as well as the ID Scope, Device ID and Key for your device

* The device will reboot, connect to WiFi and connect to Azure IoT Central

* Check the Azure IoT Central app, you will see random numbers being sent fot `value`.

* Run the `command` command to toggle a NeoPixel on the board on and off.
