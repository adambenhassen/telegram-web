const HTML_WHITESPACE_PATTERN = '[\\t\\n\\f\\r ]';
const HTML_WHITESPACE = new RegExp(HTML_WHITESPACE_PATTERN);
const HTML_TAG_START = /^<(\/?)([A-Za-z][A-Za-z0-9:-]*)(?=[\t\n\f\r \/>])/;
const HTML_SELF_CLOSING_TAG = new RegExp(`/${HTML_WHITESPACE_PATTERN}*>$`);

function isHtmlWhitespace(character) {
  return HTML_WHITESPACE.test(character || '');
}

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
  const closingTag = new RegExp(`</${name}${HTML_WHITESPACE_PATTERN}*>`, 'ig');
  closingTag.lastIndex = start;
  const match = closingTag.exec(document);
  return match ? match.index + match[0].length : document.length;
}

const RAW_TEXT_ELEMENTS = new Set(['noframes', 'noscript', 'script', 'style', 'title', 'textarea']);
const HEAD_ELEMENTS = new Set([
  'base',
  'basefont',
  'bgsound',
  'html',
  'link',
  'meta',
  'noframes',
  'noscript',
  'script',
  'style',
  'template',
  'title'
]);
const FOREIGN_CONTENT_ELEMENTS = new Set(['math', 'svg', 'template']);
const HEAD_EXITING_END_TAGS = new Set(['body', 'br', 'head', 'html']);

function skipNestedContent(document, start, name) {
  const stack = [name];
  let index = start;
  while(index < document.length && stack.length) {
    if(document.startsWith('<!--', index)) {
      index = skipComment(document, index);
      continue;
    }
    if(document[index] !== '<') {
      index++;
      continue;
    }

    const end = tagEnd(document, index);
    if(end === -1) return document.length;
    const tag = parseTag(document.slice(index, end + 1));
    if(!tag) {
      index = end + 1;
      continue;
    }
    if(tag.closing) {
      if(tag.name === stack[stack.length - 1]) stack.pop();
      index = end + 1;
      continue;
    }
    if(RAW_TEXT_ELEMENTS.has(tag.name)) {
      index = skipRawElement(document, end + 1, tag.name);
      continue;
    }
    if(FOREIGN_CONTENT_ELEMENTS.has(tag.name) && !tag.selfClosing) {
      stack.push(tag.name);
    }
    index = end + 1;
  }
  return index;
}

function parseAttributes(tag, start) {
  const attributes = new Map();
  let index = start;
  while(index < tag.length) {
    while(isHtmlWhitespace(tag[index]) || tag[index] === '/' || tag[index] === '>') index++;
    if(index >= tag.length || tag[index] === '>') break;

    const nameStart = index;
    while(index < tag.length && !isHtmlWhitespace(tag[index]) &&
      tag[index] !== '=' && tag[index] !== '/' && tag[index] !== '>') index++;
    if(index === nameStart) {
      index++;
      continue;
    }
    const name = tag.slice(nameStart, index).toLowerCase();
    while(isHtmlWhitespace(tag[index])) index++;

    let value = '';
    if(tag[index] === '=') {
      index++;
      while(isHtmlWhitespace(tag[index])) index++;
      const quote = tag[index] === '"' || tag[index] === "'" ? tag[index++] : '';
      const valueStart = index;
      if(quote) {
        while(index < tag.length && tag[index] !== quote) index++;
      } else {
        while(index < tag.length && !isHtmlWhitespace(tag[index]) && tag[index] !== '>') index++;
      }
      value = tag.slice(valueStart, index);
      if(quote && tag[index] === quote) index++;
    }
    if(!attributes.has(name)) {
      attributes.set(name, decodeHtmlEntities(value));
    }
  }
  return attributes;
}

function parseTag(tag) {
  const match = HTML_TAG_START.exec(tag);
  if(!match) return null;
  return {
    closing: Boolean(match[1]),
    name: match[2].toLowerCase(),
    selfClosing: !match[1] && HTML_SELF_CLOSING_TAG.test(tag),
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
  let headState = 'before';
  let index = 0;
  while(index < document.length) {
    if(document.startsWith('<!--', index)) {
      index = skipComment(document, index);
      continue;
    }
    if(document[index] !== '<') {
      if(headState !== 'after' && !isHtmlWhitespace(document[index])) headState = 'after';
      index++;
      continue;
    }

    const end = tagEnd(document, index);
    if(end === -1) break;
    const tag = parseTag(document.slice(index, end + 1));
    if(!tag) {
      if(headState !== 'after' && document[index + 1] !== '!' && document[index + 1] !== '?') {
        headState = 'after';
      }
      index = end + 1;
      continue;
    }

    if(tag.closing) {
      if(headState !== 'after' && HEAD_EXITING_END_TAGS.has(tag.name)) headState = 'after';
      index = end + 1;
      continue;
    }
    if(tag.name === 'head') {
      if(headState === 'before') headState = 'in';
      index = end + 1;
      continue;
    }
    if(tag.name === 'body') {
      headState = 'after';
      index = end + 1;
      continue;
    }
    if(headState === 'before' && tag.name !== 'html') {
      headState = 'after';
    }
    if(headState === 'in' && RAW_TEXT_ELEMENTS.has(tag.name)) {
      if(!HEAD_ELEMENTS.has(tag.name)) headState = 'after';
      index = skipRawElement(document, end + 1, tag.name);
      continue;
    }
    if(headState === 'in' && FOREIGN_CONTENT_ELEMENTS.has(tag.name)) {
      if(tag.name !== 'template') headState = 'after';
      index = skipNestedContent(document, end + 1, tag.name);
      continue;
    }
    if(headState === 'in' && !HEAD_ELEMENTS.has(tag.name)) {
      headState = 'after';
    }
    if(headState === 'in' && tag.name === 'meta') {
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
