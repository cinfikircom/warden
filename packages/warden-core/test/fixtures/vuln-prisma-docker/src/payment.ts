// KASITLI PCI-DSS ihlali (test fixture'ı): CVV ve PAN saklanıyor.
export interface CardRecord {
  cardNumber: string;
  cvv: string;
}

export function storeCard(db: { insert: (r: unknown) => void }, rec: CardRecord): void {
  db.insert({ cardNumber: rec.cardNumber, cvv: rec.cvv });
}
