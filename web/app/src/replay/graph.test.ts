import { describe, expect, it } from 'vitest';
import { projectFrameGraph } from './graph';
import type { GraphFrame } from './graph';

const f = (n: number, parent: string | null, symbol = `m${n}`, extra: Partial<GraphFrame> = {}): GraphFrame =>
  ({ frameId: `f${n}`, sequence: String(n), kind: 'method', symbol, parentFrameId: parent, ...extra });

const sample: GraphFrame[] = [
  f(1, null, 'Controller.create'),
  f(2, 'f1', 'Service.place'),
  f(3, 'f2', 'Repo.save'),
  f(4, 'f2', 'Repo.save'),
  f(5, 'f2', 'Repo.save'),
  f(6, 'f1', 'Audit.log'),
];

describe('frame graph projection', () => {
  it('graph_layout_is_deterministic: input order does not change the result', () => {
    const forward = projectFrameGraph(sample);
    const shuffled = projectFrameGraph([...sample].reverse());
    expect(shuffled).toEqual(forward);
    expect(projectFrameGraph(sample)).toEqual(forward);
  });

  it('collapses repeated sibling leaves with a count and keeps member ids', () => {
    const graph = projectFrameGraph(sample);
    const repo = graph.nodes.find((node) => node.symbol === 'Repo.save')!;
    expect(repo.count).toBe(3);
    expect(repo.memberFrameIds).toEqual(['f3', 'f4', 'f5']);
    expect(graph.nodeOfFrame.f5).toBe(repo.id);
    expect(graph.nodes).toHaveLength(4);
  });

  it('does not collapse siblings that have children, or that differ by symbol or kind', () => {
    const graph = projectFrameGraph([
      f(1, null, 'A'), f(2, 'f1', 'B'), f(3, 'f2', 'C'), f(4, 'f1', 'B'), f(5, 'f1', 'B', { kind: 'line_cursor' }),
    ]);
    expect(graph.nodes.filter((node) => node.symbol === 'B').map((node) => node.count)).toEqual([1, 1, 1]);
  });

  it('only merges adjacent siblings (an interloper breaks the run)', () => {
    const graph = projectFrameGraph([f(1, null, 'A'), f(2, 'f1', 'X'), f(3, 'f1', 'Y'), f(4, 'f1', 'X')]);
    expect(graph.nodes.filter((node) => node.symbol === 'X').map((node) => node.count)).toEqual([1, 1]);
  });

  it('layers by tree depth and centres a parent over its children', () => {
    const graph = projectFrameGraph(sample);
    const byId = Object.fromEntries(graph.nodes.map((node) => [node.id, node]));
    expect(byId.f1.layer).toBe(0);
    expect(byId.f2.layer).toBe(1);
    expect(byId.f3.layer).toBe(2);
    expect(graph.layers).toBe(3);
    expect(graph.columns).toBe(2);
    expect(byId.f2.column).toBe(byId.f3.column);
    expect(byId.f1.column).toBe((byId.f2.column + byId.f6.column) / 2);
  });

  it('flags a frame whose observed parent is outside the window instead of inventing a parent', () => {
    const graph = projectFrameGraph([f(10, 'f9', 'Late'), f(11, 'f10', 'Child')]);
    const late = graph.nodes.find((node) => node.id === 'f10')!;
    expect(late.parentId).toBeNull();
    expect(late.parentOutsideWindow).toBe(true);
    expect(late.layer).toBe(0);
    expect(graph.nodes.find((node) => node.id === 'f11')!.parentOutsideWindow).toBe(false);
  });

  it('a frame with no parent link is a root and not flagged', () => {
    const graph = projectFrameGraph([f(1, null), f(2, undefined as unknown as null)]);
    expect(graph.nodes.every((node) => node.layer === 0 && !node.parentOutsideWindow)).toBe(true);
  });

  it('adds async edges only when the async parent is in the window', () => {
    const graph = projectFrameGraph([f(1, null, 'A'), f(2, null, 'B', { asyncParentFrameId: 'f1' }), f(3, null, 'C', { asyncParentFrameId: 'f99' })]);
    expect(graph.edges.filter((edge) => edge.kind === 'async')).toEqual([{ from: 'f1', to: 'f2', kind: 'async' }]);
  });

  it('orders numerically, not lexically, by sequence', () => {
    const graph = projectFrameGraph([f(10, null, 'ten'), f(9, null, 'nine')]);
    expect(graph.nodes.map((node) => node.symbol)).toEqual(['nine', 'ten']);
  });

  it('handles an empty window', () => {
    expect(projectFrameGraph([])).toEqual({ nodes: [], edges: [], layers: 0, columns: 0, nodeOfFrame: {} });
  });
});
