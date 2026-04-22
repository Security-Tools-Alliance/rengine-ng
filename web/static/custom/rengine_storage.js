(function (window) {
  "use strict";

  const STORAGE_PREFIX = "rengine-";

  const hasLocalStorage = function () {
    try {
      const testKey = STORAGE_PREFIX + "test";
      window.localStorage.setItem(testKey, "1");
      window.localStorage.removeItem(testKey);
      return true;
    } catch (e) {
      return false;
    }
  };

  const storageAvailable = hasLocalStorage();
  const memoryStore = {};

  const buildKey = function (key) {
    if (!key || typeof key !== "string") return null;
    return STORAGE_PREFIX + key;
  };

  const getRaw = function (key) {
    const k = buildKey(key);
    if (!k) return null;
    if (storageAvailable) {
      try {
        return window.localStorage.getItem(k);
      } catch (e) {
        return null;
      }
    }
    return Object.prototype.hasOwnProperty.call(memoryStore, k) ? memoryStore[k] : null;
  };

  const setRaw = function (key, value) {
    const k = buildKey(key);
    if (!k) return;
    if (storageAvailable) {
      try {
        if (value === null || value === undefined) {
          window.localStorage.removeItem(k);
        } else {
          window.localStorage.setItem(k, String(value));
        }
      } catch (e) {
        // ignore quota or access errors
      }
      return;
    }
    if (value === null || value === undefined) {
      delete memoryStore[k];
    } else {
      memoryStore[k] = String(value);
    }
  };

  const removeRaw = function (key) {
    const k = buildKey(key);
    if (!k) return;
    if (storageAvailable) {
      try {
        window.localStorage.removeItem(k);
      } catch (e) {
        // ignore
      }
      return;
    }
    delete memoryStore[k];
  };

  const getPref = function (key) {
    return getRaw(key);
  };

  const setPref = function (key, value) {
    setRaw(key, value);
  };

  const getPrefJson = function (key) {
    const raw = getRaw(key);
    if (raw == null || raw === "") return null;
    try {
      return JSON.parse(raw);
    } catch (e) {
      return null;
    }
  };

  const setPrefJson = function (key, obj) {
    if (obj === undefined || obj === null) {
      removeRaw(key);
      return;
    }
    try {
      const encoded = JSON.stringify(obj);
      setRaw(key, encoded);
    } catch (e) {
      // ignore JSON errors
    }
  };

  window.rengineStorage = {
    get: getPref,
    set: setPref,
    getJson: getPrefJson,
    setJson: setPrefJson,
    remove: removeRaw,
    hasLocalStorage: function () { return storageAvailable; }
  };
})(window);

