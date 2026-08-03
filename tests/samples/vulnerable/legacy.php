<?php

$connection = mysqli_connect("localhost", "app", "secret", "shop");

$id = $_GET["id"];
$result = mysqli_query($connection, "SELECT * FROM products WHERE id = " . $id);

$action = $_POST["action"];
system("/usr/local/bin/report " . $action);

$page = $_REQUEST["page"];
include $page . ".php";

$payload = $_COOKIE["state"];
$state = unserialize($payload);

$expression = $_GET["expr"];
eval("\$value = " . $expression . ";");

$safe = escapeshellarg($_GET["name"]);
system("/usr/local/bin/greet " . $safe);

$clean = intval($_GET["limit"]);
mysqli_query($connection, "SELECT * FROM products LIMIT " . $clean);
