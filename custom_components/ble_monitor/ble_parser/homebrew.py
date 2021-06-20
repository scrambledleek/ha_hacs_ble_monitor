# Parser for Homebrew devices
import logging
import struct

_LOGGER = logging.getLogger(__name__)


HOMEBREW_TYPE_DICT = {
    0x191a: 'HB-PC01',
}


# Structured objects for data conversions
PC_STRUCT = struct.Struct("<L")


def objHomebrew_count(xobj):
    # For our counters we use 32-bit values.
    (counter,) = PC_STRUCT.unpack(xobj)
    return {"counter": counter}


# Dataobject dictionary
# {dataObject_id: (converter, bytes in data object)}
dataobject_dict = {
    0x01: (objHomebrew_count, 4),
}


def parse_homebrew(self, data, source_mac, rssi):
    # Check for adstruc length
    device_type = "Homebrew"
    msg_length = len(data)

    # _LOGGER.debug(
    #     "Homebrew packet (%d bytes):\n  %s",
    #      msg_length,
    #      ''.join('{:02X}'.format(x) for x in data[:])
    # )

    # Parse BLE message in Homebrew format
    firmware = "Homebrew"

    # Check for MAC presence in message and in service data
    homebrew_mac = data[4:10]

    if homebrew_mac != source_mac:
        _LOGGER.debug(
            "Invalid MAC address: %s",
            macAddrStr(homebrew_mac),
        )
        return None

    # Check for MAC presence in whitelist, if needed
    if self.discovery is False and homebrew_mac not in self.whitelist:
        return None, None, None

    packet_id = data[10]
    try:
        prev_packet = self.lpacket_ids[homebrew_mac]
    except KeyError:
        # Start with empty first packet
        prev_packet = None, None, None
    if prev_packet == packet_id:
        # Only process new messages
        return None
    self.lpacket_ids[homebrew_mac] = packet_id

    _LOGGER.debug("Fetching device type...")

    device_type = data[2] + (data[3] << 8)
    try:
        sensor_type = HOMEBREW_TYPE_DICT[device_type]
    except KeyError:
        if self.report_unknown:
            _LOGGER.info(
                "BLE ADV from UNKNOWN Homebrew sensor: Device type: %s, RSSI: %s, MAC: %s, ADV: %s",
                device_type,
                rssi,
                macAddrStr(homebrew_mac),
                data.hex()
            )
        _LOGGER.debug("Device unknown")
        return None

    _LOGGER.debug("Device type is: %s", sensor_type)

    # Homebrew data length = message length
    # -2 bytes Manufactuer ID
    # -2 bytes Homebrew device UUID
    # -6 bytes MAC
    # -1 Frame packet counter
    # -1 RSSI (unless extended packet)
    xdata_length = msg_length - 10 - 1 - 1
    if xdata_length < 6:
        _LOGGER.debug("Xdata length invalid")
        return None

    # First data is after the MAC and frame counter
    _LOGGER.debug("Advertising message: %s", data.hex())
    xdata_point = 11

    # Check if parse_homebrew data start and length is valid
    xdata_end_offset = -1
    if xdata_length != len(data[xdata_point:xdata_end_offset]):
        _LOGGER.debug("Invalid data length")
        return None

    result = {
        "rssi": rssi,
        "mac": ''.join('{:02X}'.format(x) for x in homebrew_mac[:]),
        "type": sensor_type,
        "packet": packet_id,
        "firmware": firmware,
        "data": True,
    }

    # We have a series of data encoded as <data_type_byte><data>.
    # The <data_type_byte> says what the following data is and how big it is.
    # When the xdata_point index is xdata_end_offset we stop.
    # Data comes back in a hash.  The keys have an index based on the number
    # of times resfunc has been seen going around the loop appended to them
    # so we can support multiple fields of the same data type.
    resfuncCounter = {}
    while (xdata_point < msg_length + xdata_end_offset):
        dataType = data[xdata_point] + 0
        _LOGGER.debug("Homebrew data type: %d", dataType)
        resfunc, numBytes = dataobject_dict.get(dataType, (None, None))
        if (numBytes is None):
            break
        _LOGGER.debug(
            "Homebrew Dict lookup for %s (%s) data type code %s got resfunc = %s, numBytes = %s",
            macAddrStr(homebrew_mac),
            sensor_type,
            dataType,
            resfunc, numBytes
        )
        xvalue = data[xdata_point + 1:xdata_point + 1 + numBytes]

        if resfunc:
            # Count number of times resFunc has been called for this packet
            # and use the count to append an index to the key, e.g.
            #   First counter parsed will be counter0
            #   Second counter parsed will be counter1
            if (resfunc in resfuncCounter):
                resfuncCounter[resfunc] += 1
            else:
                resfuncCounter[resfunc] = 0

            thisVal = resfunc(xvalue)
            newVal = {}
            for key in thisVal.keys():
                newVal[key + str(resfuncCounter[resfunc])] = thisVal[key]

            result.update(newVal)
        else:
            if self.report_unknown:
                _LOGGER.info(
                    "UNKNOWN dataobject from Homebrew device: %s, MAC: %s, ADV: %s",
                    sensor_type,
                    macAddrStr(homebrew_mac),
                    data.hex()
                )

        # Next potential data location
        xdata_point += 1 + numBytes

    _LOGGER.debug("Homebrew device packet result: %s", result)

    return result


def macAddrStr(macAddr: int):
    return ':'.join('{:02X}'.format(x) for x in macAddr)
