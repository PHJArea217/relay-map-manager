<?php
$libc_func = FFI::cdef("int symlink(const char *target, const char *source);", null);
class DomainBuilder {
	function __construct() {
		$this->ents = array();
		$this->data = array("\0\0\0\0");
		$this->data_len = 1;
	}
	function add_data($buf) {
		$buf = $buf . array("\0\0\0\0", "\0\0\0", "\0\0", "\0")[strlen($buf) & 3];
		$buf_ilen = strlen($buf) >> 2;
		$data_len_ret = $this->data_len;
		$this->data_len += $buf_ilen;
		$this->data[] = $buf;
		return $data_len_ret;
	}
	function add_ent($idx, $domain) {
		$domain_offset = $this->add_data($domain);
		$this->ents[] = pack("NN", $idx, $domain_offset);
	}
	function gen_file() {
		yield "\xf2\0\xa0\x1e";
		yield pack("N", count($this->ents));
		yield from $this->ents;
		yield from $this->data;
	}
}
function sanitize_domain($domain) {
	if (strlen($domain) == strspn($domain, "0123456789abcdefghijklmnopqrstuvwxyz._-")) {
		return $domain;
	}
	return "";
}
function index_to_ip($idx, $ip_prefix) {
	$inet = hex2bin($ip_prefix . sprintf("%04x", $idx & 0xffff));
	return inet_ntop($inet);
}
// get options
$options = json_decode(file_get_contents($argv[1]), true);

// query database
$mysqli = new mysqli(...$options["mysqli"]);
// SELECT ip, domain FROM [table] WHERE [condition]...
$mysqli_result = $mysqli->query($options["mysqli_query"]);

// init domainbuilder
$domain_builder = new DomainBuilder();

// init output file
$output_file_bin = fopen($argv[2] . "_hosts.bin.tmp", "xb");
$output_file_txt = fopen($argv[2] . "_hosts.txt.tmp", "x");

$ip_prefixes = $options["ip_prefixes"];
while ($row = $mysqli_result->fetch_row()) {
	$d = sanitize_domain($row[1]);
	if ($d == "") {
		continue;
	}
	$first = true;
	foreach ($ip_prefixes as $ip_prefix) {
		$ip_str = index_to_ip($row[0], $ip_prefix);
		if ($options["staticdir"] and $first) {
			$libc_func->symlink("X," . $ip_str, $options["staticdir"] . "/l," . $d);
		}
		fprintf($output_file_txt, "%s %s\n", $ip_str, $d);
	}
	$first = false;
	$domain_builder->add_ent($row[0], $d);
}
fclose($output_file_txt);
rename($argv[2] . "_hosts.txt.tmp", $argv[2] . "_hosts.txt");

foreach ($domain_builder->gen_file() as $b) {
	fwrite($output_file_bin, $b);
}
fclose($output_file_bin);
rename($argv[2] . "_hosts.bin.tmp", $argv[2] . "_hosts.bin");
?>
