// Minimal promise-based IndexedDB key/value store. One database ("sin"), one
// object store ("vault"). Just enough to persist the encrypted key material.

const DB_NAME = "sin";
const STORE = "vault";

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(mode, fn) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const t = db.transaction(STORE, mode);
      const store = t.objectStore(STORE);
      const request = fn(store);
      t.oncomplete = () => resolve(request?.result);
      t.onerror = () => reject(t.error);
      t.onabort = () => reject(t.error);
    });
  } finally {
    db.close();
  }
}

export const idbGet = (key) => tx("readonly", (s) => s.get(key));
export const idbSet = (key, value) => tx("readwrite", (s) => s.put(value, key));
export const idbDel = (key) => tx("readwrite", (s) => s.delete(key));
