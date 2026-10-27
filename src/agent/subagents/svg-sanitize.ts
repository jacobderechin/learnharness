import { DOMParser, XMLSerializer } from "@xmldom/xmldom";

/**
 * Generated-SVG sanitizer (security review, 2026-10-27) — defense in depth
 * IN FRONT OF the sandboxed browser renderer (headless.ts renderSvg), which
 * is the actual enforcement boundary (no file://, no network).
 *
 * A regex over attribute names is not enough: XML namespaces mean
 * `<image h:href="/abs/file">` with xmlns:h bound to the XLink namespace IS
 * an xlink:href. This pass is namespace-aware: it parses the document,
 * judges attributes by LOCAL name in every namespace, and the renderer only
 * ever sees the re-serialized result (no parser differential on the input).
 *
 *  - refuse DTDs, entity declarations, and stylesheet processing
 *    instructions outright (entity expansion and external stylesheets are
 *    classic ways around attribute filters);
 *  - drop <script>, <foreignObject> (embedded HTML), every on* handler;
 *  - drop every `href` (any namespace or none) unless it is an inline
 *    image (data:image/…) or a same-document fragment (#id);
 *  - drop CSS that could fetch: attribute or <style> text with url()
 *    pointing anywhere but #fragment / data:, or @import.
 */

const SVG_NS = "http://www.w3.org/2000/svg";

export class SvgRejectedError extends Error {}

const SAFE_REF = /^\s*(#|data:image\/)/i;
/** url(...) whose target is not a #fragment or data: URI, or @import. */
const UNSAFE_CSS = /@import|url\(\s*(['"]?)\s*(?!#|data:)/i;

type XNode = {
	nodeType: number;
	nodeName: string;
	localName?: string | null;
	namespaceURI?: string | null;
	childNodes: ArrayLike<XNode>;
	parentNode: XNode | null;
	attributes?: ArrayLike<{ name: string; localName?: string | null; value: string }>;
	removeAttribute?(name: string): void;
	removeChild(node: XNode): void;
	textContent: string | null;
	data?: string;
	target?: string;
};

function clean(node: XNode): void {
	for (const child of Array.from(node.childNodes)) {
		if (child.nodeType === 7) {
			// processing instruction
			if (/stylesheet/i.test(child.target ?? child.nodeName)) throw new SvgRejectedError("stylesheet processing instructions are not allowed");
			node.removeChild(child);
			continue;
		}
		if (child.nodeType !== 1) continue;
		const local = (child.localName ?? child.nodeName).toLowerCase();
		if (local === "script" || local === "foreignobject") {
			node.removeChild(child);
			continue;
		}
		if (local === "style" && UNSAFE_CSS.test(child.textContent ?? "")) {
			node.removeChild(child);
			continue;
		}
		for (const attr of Array.from(child.attributes ?? [])) {
			const name = (attr.localName ?? attr.name.split(":").pop() ?? "").toLowerCase();
			const drop =
				name.startsWith("on") ||
				(name === "href" && !SAFE_REF.test(attr.value)) ||
				UNSAFE_CSS.test(attr.value);
			if (drop) child.removeAttribute!(attr.name);
		}
		clean(child);
	}
}

/** Parse, clean, and re-serialize a generated SVG; throws SvgRejectedError
 *  for documents that must not be rendered at all. */
export function sanitizeSvg(svg: string): string {
	if (/<!DOCTYPE|<!ENTITY/i.test(svg)) throw new SvgRejectedError("SVG documents with a DTD or entity declarations are not allowed");
	let doc: { documentElement: XNode | null; childNodes: ArrayLike<XNode> };
	try {
		doc = new DOMParser({
			onError: (level: string, message: string) => {
				if (level !== "warning") throw new SvgRejectedError(`invalid SVG: ${message}`);
			},
		}).parseFromString(svg.trim(), "image/svg+xml") as unknown as typeof doc;
	} catch (err) {
		throw err instanceof SvgRejectedError ? err : new SvgRejectedError(`invalid SVG: ${(err as Error).message}`);
	}
	// Document-level processing instructions sit beside the root, not in it.
	for (const node of Array.from(doc.childNodes)) {
		if (node.nodeType === 7 && /stylesheet/i.test(node.target ?? node.nodeName)) {
			throw new SvgRejectedError("stylesheet processing instructions are not allowed");
		}
	}
	const root = doc.documentElement;
	if (!root || (root.localName ?? root.nodeName) !== "svg" || root.namespaceURI !== SVG_NS) {
		throw new SvgRejectedError("the document root must be an <svg> element in the SVG namespace");
	}
	for (const attr of Array.from(root.attributes ?? [])) {
		const name = (attr.localName ?? attr.name).toLowerCase();
		if (name.startsWith("on") || UNSAFE_CSS.test(attr.value)) root.removeAttribute!(attr.name);
	}
	clean(root);
	return new XMLSerializer().serializeToString(root as never);
}
