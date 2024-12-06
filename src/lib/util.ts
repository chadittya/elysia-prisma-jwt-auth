function getExpTimestamp(second: number) {
  const currentTimeMillis = Date.now();
  const secondIntoMillis = second * 1000;
  const expirationTimeMillies = currentTimeMillis + secondIntoMillis;

  return Math.floor(expirationTimeMillies / 1000);
}

export { getExpTimestamp };
