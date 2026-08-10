// A JSON Schema (2020-12 subset) validator in ~200 dependency-free lines.
//
// WHY NOT ajv: this repo must validate with nothing but `node`. The registry is
// the file the Astra client trusts; a validation step that only runs where
// `npm install` succeeded is a validation step that stops running the first
// time a network is unavailable, and nobody notices until a bad listing ships.
//
// The subset is deliberately small AND deliberately strict: an unknown keyword
// is a hard error, not a no-op. A validator that silently ignores the one
// keyword the schema author was relying on is worse than no validator, because
// it reports success. If you need a keyword that is not here, implement it.

const KNOWN = new Set([
  "$schema", "$id", "$ref", "$defs", "$comment",
  "title", "description", "examples", "default", "deprecated",
  "type", "enum", "const",
  "properties", "required", "additionalProperties", "patternProperties",
  "propertyNames", "minProperties", "maxProperties",
  "items", "prefixItems", "minItems", "maxItems", "uniqueItems",
  "minLength", "maxLength", "pattern",
  "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
  "allOf", "anyOf", "oneOf", "not",
]);

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v; // string | boolean | object
}

function typeMatches(actual, expected) {
  if (expected === "number") return actual === "number" || actual === "integer";
  return actual === expected;
}

function resolveRef(root, ref) {
  if (ref === "#") return root;
  if (!ref.startsWith("#/")) throw new Error(`unsupported $ref: ${ref}`);
  let node = root;
  for (const raw of ref.slice(2).split("/")) {
    const key = decodeURIComponent(raw.replace(/~1/g, "/").replace(/~0/g, "~"));
    node = node?.[key];
    if (node === undefined) throw new Error(`unresolvable $ref: ${ref}`);
  }
  return node;
}

function check(schema, value, path, root, errors) {
  if (schema === true) return;
  if (schema === false) {
    errors.push({ path, message: "no value is allowed here" });
    return;
  }
  for (const key of Object.keys(schema)) {
    if (!KNOWN.has(key)) {
      throw new Error(
        `${path}: schema uses unsupported keyword "${key}" — implement it in tools/lib/jsonschema.mjs rather than shipping a schema that is not enforced`,
      );
    }
  }

  if (schema.$ref !== undefined) {
    check(resolveRef(root, schema.$ref), value, path, root, errors);
  }

  const actual = typeOf(value);

  if (schema.type !== undefined) {
    const want = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!want.some((t) => typeMatches(actual, t))) {
      errors.push({ path, message: `expected ${want.join(" or ")}, got ${actual}` });
      return; // further keywords would only produce noise
    }
  }

  if (schema.const !== undefined && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    errors.push({ path, message: `must be ${JSON.stringify(schema.const)}` });
  }
  if (schema.enum !== undefined && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) {
    errors.push({ path, message: `must be one of ${schema.enum.map((e) => JSON.stringify(e)).join(", ")}` });
  }

  if (actual === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push({ path, message: `shorter than ${schema.minLength} characters` });
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push({ path, message: `longer than ${schema.maxLength} characters` });
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) {
      errors.push({ path, message: `does not match /${schema.pattern}/` });
    }
  }

  if (actual === "number" || actual === "integer") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push({ path, message: `less than ${schema.minimum}` });
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push({ path, message: `greater than ${schema.maximum}` });
    }
    if (schema.exclusiveMinimum !== undefined && value <= schema.exclusiveMinimum) {
      errors.push({ path, message: `must be greater than ${schema.exclusiveMinimum}` });
    }
    if (schema.exclusiveMaximum !== undefined && value >= schema.exclusiveMaximum) {
      errors.push({ path, message: `must be less than ${schema.exclusiveMaximum}` });
    }
    if (schema.multipleOf !== undefined && value % schema.multipleOf !== 0) {
      errors.push({ path, message: `not a multiple of ${schema.multipleOf}` });
    }
  }

  if (actual === "array") {
    const prefix = schema.prefixItems ?? [];
    prefix.forEach((sub, i) => {
      if (i < value.length) check(sub, value[i], `${path}[${i}]`, root, errors);
    });
    if (schema.items !== undefined) {
      for (let i = prefix.length; i < value.length; i++) {
        check(schema.items, value[i], `${path}[${i}]`, root, errors);
      }
    }
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push({ path, message: `needs at least ${schema.minItems} items` });
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      errors.push({ path, message: `has more than ${schema.maxItems} items` });
    }
    if (schema.uniqueItems) {
      const seen = new Set();
      for (const item of value) {
        const k = JSON.stringify(item);
        if (seen.has(k)) errors.push({ path, message: `duplicate item ${k}` });
        seen.add(k);
      }
    }
  }

  if (actual === "object") {
    const keys = Object.keys(value);
    for (const req of schema.required ?? []) {
      if (!Object.hasOwn(value, req)) {
        errors.push({ path, message: `missing required property "${req}"` });
      }
    }
    if (schema.minProperties !== undefined && keys.length < schema.minProperties) {
      errors.push({ path, message: `needs at least ${schema.minProperties} properties` });
    }
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) {
      errors.push({ path, message: `has more than ${schema.maxProperties} properties` });
    }
    const patterns = Object.entries(schema.patternProperties ?? {});
    for (const key of keys) {
      const sub = `${path}.${key}`;
      let matched = false;
      if (schema.properties && Object.hasOwn(schema.properties, key)) {
        matched = true;
        check(schema.properties[key], value[key], sub, root, errors);
      }
      for (const [pattern, ps] of patterns) {
        if (new RegExp(pattern, "u").test(key)) {
          matched = true;
          check(ps, value[key], sub, root, errors);
        }
      }
      if (schema.propertyNames !== undefined) {
        check(schema.propertyNames, key, `${path} property name "${key}"`, root, errors);
      }
      if (!matched && schema.additionalProperties !== undefined) {
        if (schema.additionalProperties === false) {
          errors.push({ path, message: `unknown property "${key}"` });
        } else {
          check(schema.additionalProperties, value[key], sub, root, errors);
        }
      }
    }
  }

  for (const sub of schema.allOf ?? []) check(sub, value, path, root, errors);
  if (schema.anyOf !== undefined) {
    const ok = schema.anyOf.some((sub) => {
      const local = [];
      check(sub, value, path, root, local);
      return local.length === 0;
    });
    if (!ok) errors.push({ path, message: "matches none of the allowed shapes (anyOf)" });
  }
  if (schema.oneOf !== undefined) {
    const hits = schema.oneOf.filter((sub) => {
      const local = [];
      check(sub, value, path, root, local);
      return local.length === 0;
    }).length;
    if (hits !== 1) {
      errors.push({ path, message: `matches ${hits} of the allowed shapes (oneOf wants exactly 1)` });
    }
  }
  if (schema.not !== undefined) {
    const local = [];
    check(schema.not, value, path, root, local);
    if (local.length === 0) errors.push({ path, message: "matches a forbidden shape (not)" });
  }
}

/**
 * @returns {{path: string, message: string}[]} empty when the value is valid
 */
export function validate(schema, value, rootPath = "$") {
  const errors = [];
  check(schema, value, rootPath, schema, errors);
  return errors;
}
