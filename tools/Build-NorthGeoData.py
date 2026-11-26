import argparse
import csv
import gzip
import ipaddress
import json
from pathlib import Path

def rounded(item):
    return [rounded(value) for value in item] if isinstance(item, list) else round(item, 3)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("geojson", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for version, width in ((4, 4), (6, 16)):
        ranges = []
        with gzip.open(args.csv, "rt", encoding="utf-8", newline="") as stream:
            for first, last, country in csv.reader(stream):
                if country == "ZZ" or len(country) != 2 or not country.isascii() or not country.isupper():
                    continue
                start = ipaddress.ip_address(first)
                if start.version != version:
                    continue
                stop = ipaddress.ip_address(last)
                ranges.append((int(start), int(stop), country))
        ranges.sort()
        with (args.output / f"country-{version}.bin").open("wb") as out:
            for start, stop, country in ranges:
                out.write(start.to_bytes(width, "big") + stop.to_bytes(width, "big") + country.encode("ascii"))

    source = json.loads(args.geojson.read_text(encoding="utf-8"))
    features = []
    for feature in source["features"]:
        properties = feature["properties"]
        code = properties["ISO_A2_EH"]
        if len(code) != 2:
            code = properties["ISO_A2"]
        geometry = feature["geometry"]
        features.append({"type": "Feature", "properties": {
            "code": code, "name": properties["ADMIN"],
            "lon": properties["LABEL_X"], "lat": properties["LABEL_Y"],
        }, "geometry": {"type": geometry["type"], "coordinates": rounded(geometry["coordinates"])}})
    (args.output / "world.json").write_text(
        json.dumps({"type": "FeatureCollection", "features": features}, separators=(",", ":"), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

if __name__ == "__main__":
    main()
