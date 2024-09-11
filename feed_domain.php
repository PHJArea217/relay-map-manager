<?php
$options = json_decode(file_get_contents($argv[1]), true);
$mysqli = new mysqli(...$options["mysqli"] /*"localhost", "username", "password", "database"*/);
$stmt_check = $mysqli->prepare("SELECT id FROM domains_tbl_tmp WHERE domain = ? LIMIT 1");
$stmt_insert = $mysqli->prepare("INSERT INTO domains_tbl_tmp (domain) VALUES (?)");
function feed_domain($domain) {
	global $stmt_check;
	global $stmt_insert;
	global $mysqli;
	// Fast path check
	$stmt_check->bind_param("s", $domain);
	$stmt_check->execute();
	$check_result = $stmt_check->get_result();
	$first_row = $check_result->fetch_row();
	if ($first_row) {
		return intval($first_row[0]);
	}
	try {
		$stmt_insert->bind_param("s", $domain);
		$stmt_insert->execute();
		return intval($mysqli->insert_id);
	} catch (Exception $e) {
		// Slow path check. Wastes an id.
		return 0;
	}
}
function feed_domain_sanitized($domain) {
	$domain_l = strspn($domain, "abcdefghijklmnopqrstuvwxyz0123456789-_.");
	$domain_s = substr($domain, 0, $domain_l);
	return feed_domain($domain_s);
}
if ($argv[2]) {
	switch ($argv[2]) {
		case '.':
			foreach (array_slice($argv, 3) as $domain) {
				echo strval(feed_domain_sanitized($domain)) . '\n';
			}
		case '/':
			$domains = json_decode(file_get_contents($argv[3]));
			foreach ($domains as $domain) {
				echo strval(feed_domain_sanitized($domain)) . '\n';
			}
	}
	exit;
}
$domain_recv_sock = socket_create(AF_UNIX, SOCK_DGRAM, 0);
socket_bind($domain_recv_sock, $options["socket_path"]);
while (true) {
	$recv_data = "";
	socket_recv($domain_recv_sock, $recv_data, 512);
	if (str_starts_with($recv_data, "sni_proxy_needed_for \"")) {
		$domain = substr($recv_data, 22, 490);
		feed_domain_sanitized($domain);
	}
}
?>
