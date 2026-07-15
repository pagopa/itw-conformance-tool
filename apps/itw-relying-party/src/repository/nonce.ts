interface Nonce {
  expiresAt: number;
  id: string;
}

export class NonceRepository {
  private readonly nonces: Nonce[] = [];

  public list() {
    return this.nonces;
  }

  public get(nonceId: string) {
    const nonce = this.nonces.find(({ id }) => id === nonceId);
    if (!nonce) {
      throw new Error(`Nonce ${nonceId} not found`);
    }
    return nonce;
  }

  public delete(nonceId: string) {
    const nonce = this.nonces.find(({ id }) => id === nonceId);
    if (!nonce) {
      throw new Error(`Nonce ${nonceId} not found`);
    }
    const index = this.nonces.findIndex((el) => el.id === nonceId);
    if (index === -1) {
      throw new Error(`Nonce ${nonceId} not found`);
    }
    this.nonces.splice(index, 1);
  }

  public insert(nonceId: string) {
    // we delete the nonce after 5 minutes (aligned with the request object TTL)
    this.nonces.push({
      expiresAt: Date.now() + 5 * 60 * 1000,
      id: nonceId
    });
  }

  public deleteExpiredNonces() {
    const now = Date.now();
    for (const { expiresAt, id } of this.nonces) {
      if (expiresAt < now) {
        this.delete(id);
      }
    }
  }
}
