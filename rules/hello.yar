rule HelloString {
  strings:
    $a = "hello" ascii wide
  condition:
    $a
}
