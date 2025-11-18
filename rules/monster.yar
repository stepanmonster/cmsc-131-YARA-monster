rule Monster {
  strings:
    $a = "monster" ascii wide
  condition:
    $a
}
