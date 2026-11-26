/** The Java runtime appends a digest to method identities. Keep it in Details. */
export function displaySymbol(symbol: string): string {
  return symbol.replace(/#m1:[a-f0-9]{64}$/, '');
}
