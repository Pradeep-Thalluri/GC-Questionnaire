import json
import os
import sys
from collections import defaultdict
import argparse
import csv

try:
    import requests
except Exception as e:
    print("This script requires the 'requests' package. Install via: pip install requests", file=sys.stderr)
    sys.exit(1)

# Try multiple years in case some datasets change availability
CENSUS_BASES = [
    "https://api.census.gov/data/2023/pep/population",
    "https://api.census.gov/data/2022/pep/population",
    "https://api.census.gov/data/2021/pep/population",
]
# We fetch all places with their display NAME and FIPS. Parsing state name from NAME suffix.
BASE_PARAMS = {
    "get": "NAME",
    "for": "place:*",
}

STATE_NAME_FIXES = {
    # Ensure consistency with form state names
    # The API returns full state names in NAME's comma suffix
}


def fetch_places():
    last_err = None
    for url in CENSUS_BASES:
        try:
            resp = requests.get(url, params=BASE_PARAMS, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            break
        except Exception as e:
            last_err = e
            data = None
            continue
    if data is None:
        raise last_err or RuntimeError("Failed to fetch from Census API")
    headers = data[0]
    rows = data[1:]
    name_idx = headers.index("NAME")
    results = []
    for row in rows:
        name = row[name_idx]
        # NAME format: "City city, State" or "Town town, State", include CDPs etc.
        if "," not in name:
            # Skip malformed
            continue
        place_name, state_name = [part.strip() for part in name.rsplit(",", 1)]
        # Normalize state name capitalization
        state_name = state_name
        # Some place names include type; keep full displayed name for user clarity
        results.append((state_name, place_name))
    return results


def build_index(places):
    by_state = defaultdict(set)
    for state_name, place_name in places:
        by_state[state_name].add(place_name)
    # Convert to sorted lists
    return {state: sorted(list(cities)) for state, cities in sorted(by_state.items(), key=lambda x: x[0])}


ABBR_TO_STATE = {
    'AL':'Alabama','AK':'Alaska','AZ':'Arizona','AR':'Arkansas','CA':'California','CO':'Colorado','CT':'Connecticut','DE':'Delaware',
    'DC':'District of Columbia','FL':'Florida','GA':'Georgia','HI':'Hawaii','ID':'Idaho','IL':'Illinois','IN':'Indiana','IA':'Iowa',
    'KS':'Kansas','KY':'Kentucky','LA':'Louisiana','ME':'Maine','MD':'Maryland','MA':'Massachusetts','MI':'Michigan','MN':'Minnesota',
    'MS':'Mississippi','MO':'Missouri','MT':'Montana','NE':'Nebraska','NV':'Nevada','NH':'New Hampshire','NJ':'New Jersey','NM':'New Mexico',
    'NY':'New York','NC':'North Carolina','ND':'North Dakota','OH':'Ohio','OK':'Oklahoma','OR':'Oregon','PA':'Pennsylvania','RI':'Rhode Island',
    'SC':'South Carolina','SD':'South Dakota','TN':'Tennessee','TX':'Texas','UT':'Utah','VT':'Vermont','VA':'Virginia','WA':'Washington',
    'WV':'West Virginia','WI':'Wisconsin','WY':'Wyoming'
}


def parse_gazetteer_file(path: str):
    places = []
    # Gazetteer files are typically tab-delimited with headers including NAME and USPS
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters='\t,')
        reader = csv.DictReader(f, dialect=dialect)
        if 'NAME' not in reader.fieldnames:
            raise RuntimeError('Gazetteer file missing NAME column')
        # Some variants include USPS; otherwise parse state from NAME suffix
        for row in reader:
            name = row.get('NAME', '').strip()
            usps = row.get('USPS', '').strip()
            if not name:
                continue
            if usps:
                state_full = ABBR_TO_STATE.get(usps, usps)
                # Remove trailing ", ST" from name when USPS provided
                if name.endswith(f", {usps}"):
                    place_name = name[:-(len(usps)+2)]
                else:
                    place_name = name
            else:
                if ',' in name:
                    place_name, state_part = [p.strip() for p in name.rsplit(',', 1)]
                    # If state_part is abbr, map to full
                    state_full = ABBR_TO_STATE.get(state_part, state_part)
                else:
                    # Skip if we cannot determine state
                    continue
            places.append((state_full, place_name))
    return places


def parse_simple_state_city_csv(path: str):
    places = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        sample = f.read(2048)
        f.seek(0)
        dialect = csv.Sniffer().sniff(sample, delimiters='\t,;')
        reader = csv.DictReader(f, dialect=dialect)
        # Case-insensitive header lookup
        headers = {h.lower(): h for h in (reader.fieldnames or [])}
        # Accept variants: state, state_name, state code; city
        city_col = headers.get('city')
        state_col = headers.get('state') or headers.get('state_name') or headers.get('state code') or headers.get('state_code')
        if not state_col or not city_col:
            raise RuntimeError('CSV must contain City and State/State_Name/State_Code headers')
        for row in reader:
            state_val = (row.get(state_col) or '').strip()
            city_name = (row.get(city_col) or '').strip()
            if not state_val or not city_name:
                continue
            # Normalize state if it's 2-letter code
            state_name = state_val
            st_up = state_val.strip()
            if len(st_up) == 2:
                st_up = st_up.upper()
                state_name = ABBR_TO_STATE.get(st_up, state_val)
            places.append((state_name, city_name))
    return places


def main():
    parser = argparse.ArgumentParser(description='Build us_cities.json grouped by state')
    parser.add_argument('--from-file', dest='from_file', help='Path to local Census Gazetteer place file (txt/csv). If provided, skips API fetch.')
    args = parser.parse_args()

    if args.from_file:
        print(f"Building from local file: {args.from_file}")
        # Auto-detect simple vs gazetteer format
        with open(args.from_file, 'r', encoding='utf-8', errors='ignore') as f:
            header_line = f.readline()
        header_lower = header_line.lower()
        if 'state' in header_lower and 'city' in header_lower:
            places = parse_simple_state_city_csv(args.from_file)
        else:
            places = parse_gazetteer_file(args.from_file)
    else:
        print("Fetching U.S. places from U.S. Census API ...")
        places = fetch_places()
    out_path = os.path.join(os.path.dirname(__file__), '..', 'static', 'us_cities.json')
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    print(f"Fetched {len(places)} records. Building state->cities index ...")
    index = build_index(places)

    # Optional: map District of Columbia explicitly
    if "District of Columbia" not in index and "District Of Columbia" in index:
        index["District of Columbia"] = index.pop("District Of Columbia")

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    print(f"Wrote {out_path}")


if __name__ == '__main__':
    try:
        main()
    except requests.HTTPError as e:
        print(f"HTTP error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Failed: {e}", file=sys.stderr)
        sys.exit(3)
