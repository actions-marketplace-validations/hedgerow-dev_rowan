<?php
function resize_image($filename) {
    $out = shell_exec("convert " . $_GET['file'] . " -resize 100x100 " . $filename);
    return $out;
}
