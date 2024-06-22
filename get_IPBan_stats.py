from pathlib import Path
from glob import iglob

# DEPTH : CIDR Block Depth (8x)
DEPTH = 1
PRINT_PADDING = 2
IGNORE_THRESHOLD = 2
IPBAN_DIR = Path("C:/Program Files/IPBan")
SEARCH_TARGETS = (
	"|WARN|IPBan|Login failure:",
)



def get_failed_ips() -> list[str]:
	failed_ips = list()

	for filename in iglob(str(IPBAN_DIR/"logfile*")):

		with open(filename, 'r', encoding="utf-8") as file:
			for line in file.readlines():
				for search_target in SEARCH_TARGETS:
					if search_target in line:

						failed_ip = line.split(search_target)[-1].split(",")[0].strip()
						failed_ips.append(failed_ip)

	return failed_ips

def ips_to_ranges(ips: list[str]) -> dict[str, int]:
	ranges = dict()

	for ip in ips:
		range = _parse_ip_to_range(ip)
		ranges[range] = ranges.get(range, 0) + 1

	return ranges

def _parse_ip_to_range(ip: str) -> str:
	return ".".join(ip.split(".")[:-DEPTH]) + "." + ".".join("0" for _ in range(DEPTH)) + "/" + str( 32 - (8 * DEPTH) )

def as_sorted_pretty_string(nested_dict, indent=2, threshold=0) -> str:
	sorted_dict = dict( sorted(nested_dict.items(), key=lambda range: range[1], reverse=True) )

	result = "\n" + " "*indent + f"{'IP ADDR':<20}" + f"{'CIDR':<4}" + "      " + f"{'ATTEMPT(s)':<02}" + "\n\n"

	for k,v in sorted_dict.items():
		if v < threshold:
			continue
		result += " "*indent + ".".join( f"{a:_>3}" for a in k.split('/')[0].split('.') ) + "  /  " + k.split('/')[1] + "    --  " + f"{v:_>2}" + "\n"
	return result


if __name__ == "__main__":
	failed_ips = get_failed_ips()
	failed_ranges = ips_to_ranges(failed_ips)

	print(
		as_sorted_pretty_string(
			failed_ranges, 
			indent=PRINT_PADDING, 
			threshold=IGNORE_THRESHOLD
		)
	)
