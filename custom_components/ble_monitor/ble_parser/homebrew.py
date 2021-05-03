# Parser for Homebrew BLE advertisements
import logging
import struct

_LOGGER = logging.getLogger(__name__)

# Sensors type dictionary
# {device type code: (device name, binary?)}
HOMEBREW_TYPE_DICT = {
    b'\x1A\x19': ('HB-PC01', False),
}

# Structured objects for data conversions
PC_STRUCT = struct.Struct("<L")


# Advertisement conversion of measurement data
def objHomebrew_count(xobj):
    # For our counters we use 32-bit values.
    (counter,) = PC_STRUCT.unpack(xobj)
    return {"counter": counter}


# Dataobject dictionary
# {dataObject_id: (converter, binary, measuring)
homebrew_dataobject_dict = {
    b'\x00\x01': (objHomebrew_count, False, True, 4),
}


# Parse Homebrew bluetooth data
# homebrew_index is the start of the Homebrew advertising data structure
def parse_homebrew(self, data, homebrew_index, is_ext_packet):
    try:
        # _LOGGER.debug(
        #     "Homebrew packet with homebrew_index %s (%s)\n  %s",
        #     homebrew_index,
        #     is_ext_packet,
        #     ''.join('{:02X}'.format(x) for x in data[:])
        # )

        # Parse BLE message in Homebrew format
        firmware = "Homebrew"

        # Check BTLE msg size
        msg_length = data[2] + 3
        if msg_length != len(data):
            raise NoValidError("Invalid index")

        # _LOGGER.debug("  Length %s", msg_length)

        # Check for MAC presence in message and in service data
        homebrew_mac = data[homebrew_index + 3:homebrew_index + 9]

        mac_index = homebrew_index - (22 if is_ext_packet else 8)
        source_mac_reversed = data[mac_index:mac_index + 6]
        source_mac = source_mac_reversed[::-1]
        if homebrew_mac != source_mac:
            raise NoValidError("Invalid MAC address")

        # Check for MAC presence in whitelist, if needed
        if self.discovery is False and source_mac_reversed not in self.whitelist:
            return None, None, None

        packet_id = data[homebrew_index + 9]
        try:
            prev_packet = self.lpacket_ids[homebrew_index]
        except KeyError:
            # Start with empty first packet
            prev_packet = None, None, None
        if prev_packet == packet_id:
            # Only process new messages
            return None, None, None
        self.lpacket_ids[homebrew_index] = packet_id

        # Extract RSSI byte
        rssi_index = 18 if is_ext_packet else msg_length - 1
        (rssi,) = struct.unpack("<b", data[rssi_index:rssi_index + 1])

        # Strange positive RSSI workaround
        if rssi > 0:
            rssi = -rssi

        _LOGGER.debug("Fetching device type...")

        device_type = data[homebrew_index + 1:homebrew_index + 3]
        try:
            sensor_type, binary_data = HOMEBREW_TYPE_DICT[device_type]
        except KeyError:
            if self.report_unknown:
                _LOGGER.info(
                    "BLE ADV from UNKNOWN Homebrew sensor: RSSI: %s, MAC: %s, ADV: %s",
                    rssi,
                    ''.join('{:02X}'.format(x) for x in homebrew_mac[:]),
                    data.hex()
                )
            raise NoValidError("Device unknown")

        _LOGGER.debug("Device type is: %s", sensor_type)

        # Homebrew data length = message length
        # -all bytes before Homebrew UUID
        # -2 bytes Homebrew UUID
        # -6 bytes MAC
        # -1 Frame packet counter
        # -1 RSSI (unless extended packet)
        xdata_length = msg_length - homebrew_index - 10 - (0 if is_ext_packet else 1)
        if xdata_length < 6:
            raise NoValidError("Xdata length invalid")

        # First data is after the MAC and frame counter
        xdata_point = homebrew_index + 10

        # Check if parse_homebrew data start and length is valid
        xdata_end_offset = (0 if is_ext_packet else -1)
        if xdata_length != len(data[xdata_point:xdata_end_offset]):
            raise NoValidError("Invalid data length")

        result = {
            "rssi": rssi,
            "mac": ''.join('{:02X}'.format(x) for x in homebrew_mac[:]),
            "type": sensor_type,
            "packet": packet_id,
            "firmware": firmware,
            "data": True,
        }
        binary = False
        measuring = False

        # We have a series of data encoded as <data_type_byte><data>.
        # The <data_type_byte> says what the following data is and how big it is.
        # When the xdata_point index is xdata_end_offset we stop.
        # Data comes back in a hash.  The keys have an index based on the number
        # of times resfunc has been seen going around the loop appended to them
        # so we can support multiple fields of the same data type.
        resfuncCounter = {}
        while (xdata_point < msg_length + xdata_end_offset):
            dataType = struct.pack("BB", 0, data[xdata_point])
            resfunc, tbinary, tmeasuring, numBytes = homebrew_dataobject_dict.get(dataType, (None, None, None, None))
            if (numBytes is None):
                break
            _LOGGER.debug(
                "Homebrew Dict lookup for %s (%s) data type code %s got resfunc = %s, tbinary = %s, tmeasuring = %s, numBytes = %s",
                ''.join('{:02X}'.format(x) for x in homebrew_mac[:]),
                sensor_type,
                dataType,
                resfunc, tbinary, tmeasuring, numBytes
            )
            xvalue = data[xdata_point + 1:xdata_point + 1 + numBytes]

            if resfunc:
                binary = binary or tbinary
                measuring = measuring or tmeasuring

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
                        ''.join('{:02X}'.format(x) for x in homebrew_mac[:]),
                        data.hex()
                    )
            binary |= binary and binary_data

            # Next potential data location
            xdata_point += 1 + numBytes

        _LOGGER.debug("Homebrew device packet result: %s", result)

        return result, binary, measuring

    except NoValidError as nve:
        _LOGGER.debug("Invalid data: %s", nve)

    return None, None, None


class NoValidError(Exception):
    pass
