import { UUID } from 'uuidv7';

const convertUuidToUnix = (uuid: string) => {
  const timestampBytes = new Uint8Array(8);
  timestampBytes.set(
    new Uint8Array(UUID.parse(uuid).bytes.buffer.slice(0, 6)),
    2
  );
  const timestampMs = new DataView(timestampBytes.buffer).getBigUint64(0, false);

  const unixTimestamp = Number(timestampMs) / 1000;

  return unixTimestamp;
};
