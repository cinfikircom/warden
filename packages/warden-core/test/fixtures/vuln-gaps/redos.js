// ReDoS: iç içe niceleyici — kötü girdide üstel backtracking.
export function bankaKoduGecerliMi(bankRouting) {
  const regexPattern = /([0-9]+)+\#/;
  return regexPattern.test(bankRouting);
}

// Güvenli: tek niceleyici, lineer.
export function postaKoduGecerliMi(zip) {
  const safe = /^[0-9]{5}$/;
  return safe.test(zip);
}
