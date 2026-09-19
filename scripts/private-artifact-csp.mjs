function tagEnd(document, start) {
  let quote = '';
  for(let index = start + 1; index < document.length; index++) {
    const character = document[index];
    if(quote) {
      if(character === quote) quote = '';
    } else if(character === '"' || character === "'") {
      quote = character;
    } else if(character === '>') {
      return index;
    }
  }
  return -1;
}

function skipComment(document, start) {
  const end = document.indexOf('-->', start + 4);
  return end === -1 ? document.length : end + 3;
}

function skipRawElement(document, start, name) {
  const closingTag = new RegExp(`</${name}\\s*>`, 'ig');
  closingTag.lastIndex = start;
  const match = closingTag.exec(document);
  return match ? match.index + match[0].length : document.length;
}

function parseAttributes(tag, start) {
  const attributes = new Map();
  let index = start;
  while(index < tag.length) {
    while(/[\s/>]/.test(tag[index] || '')) index++;
    if(index >= tag.length || tag[index] === '>') break;

    const nameStart = index;
    while(index < tag.length && !/[\s=/>]/.test(tag[index])) index++;
    if(index === nameStart) {
      index++;
      continue;
    }
    const name = tag.slice(nameStart, index).toLowerCase();
    while(/\s/.test(tag[index] || '')) index++;

    let value = '';
    if(tag[index] === '=') {
      index++;
      while(/\s/.test(tag[index] || '')) index++;
      const quote = tag[index] === '"' || tag[index] === "'" ? tag[index++] : '';
      const valueStart = index;
      if(quote) {
        while(index < tag.length && tag[index] !== quote) index++;
      } else {
        while(index < tag.length && !/[\s>]/.test(tag[index])) index++;
      }
      value = tag.slice(valueStart, index);
      if(quote && tag[index] === quote) index++;
    }
    attributes.set(name, decodeHtmlEntities(value));
  }
  return attributes;
}

function parseTag(tag) {
  const match = /^<\s*(\/?)\s*([A-Za-z][A-Za-z0-9:-]*)/.exec(tag);
  if(!match) return null;
  return {
    closing: Boolean(match[1]),
    name: match[2].toLowerCase(),
    attributes: match[1] ? new Map() : parseAttributes(tag, match[0].length)
  };
}

function decodeHtmlEntities(value) {
  return value.replace(/&(?:#(\d+)|#x([0-9a-f]+)|amp|quot|apos|lt|gt);/gi,
    (entity, decimal, hexadecimal) => {
      if(decimal) return String.fromCodePoint(Number(decimal));
      if(hexadecimal) return String.fromCodePoint(parseInt(hexadecimal, 16));
      return {
        '&amp;': '&',
        '&quot;': '"',
        '&apos;': "'",
        '&lt;': '<',
        '&gt;': '>'
      }[entity.toLowerCase()] || entity;
    });
}

export function readHeadContentSecurityPolicies(document) {
  if(typeof document !== 'string') return [];

  const policies = [];
  let inHead = false;
  let index = 0;
  while(index < document.length) {
    if(document.startsWith('<!--', index)) {
      index = skipComment(document, index);
      continue;
    }
    if(document[index] !== '<') {
      index++;
      continue;
    }

    const end = tagEnd(document, index);
    if(end === -1) break;
    const tag = parseTag(document.slice(index, end + 1));
    if(!tag) {
      index = end + 1;
      continue;
    }

    if(tag.closing) {
      if(tag.name === 'head') break;
      index = end + 1;
      continue;
    }
    if(tag.name === 'head') {
      inHead = true;
      index = end + 1;
      continue;
    }
    if(tag.name === 'script' || tag.name === 'style') {
      index = skipRawElement(document, end + 1, tag.name);
      continue;
    }
    if(inHead && tag.name === 'meta') {
      const httpEquiv = tag.attributes.get('http-equiv')?.trim().toLowerCase();
      const content = tag.attributes.get('content');
      if(httpEquiv === 'content-security-policy' && content !== undefined) {
        policies.push(content);
      }
    }
    index = end + 1;
  }
  return policies;
}
