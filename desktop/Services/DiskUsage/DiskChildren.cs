using System.Collections;

namespace Suhang.Desktop.DiskUsage;

// Ordered during enumeration: bounded snapshots never sort or copy a huge directory.
internal sealed class DiskChildren : IReadOnlyList<DiskNode>
{
    readonly SortedSet<DiskNode> nodes = new(DiskOrder.Instance);
    public int Count => nodes.Count;
    public DiskNode this[int index] => nodes.ElementAt(index);
    internal bool Add(DiskNode node) => nodes.Add(node);
    internal bool Remove(DiskNode node) => nodes.Remove(node);
    internal bool Contains(DiskNode node) => nodes.TryGetValue(node,out var found)&&ReferenceEquals(node,found);
    public IEnumerator<DiskNode> GetEnumerator() => nodes.GetEnumerator();
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
