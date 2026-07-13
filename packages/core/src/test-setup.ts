import { parse as parseYaml } from 'yaml';
import { registerYamlParser } from './parse/detect';

// Mirrors what the parse worker does at startup.
registerYamlParser(parseYaml);
