from specimen.provenance import map_technique, reconstruct
from specimen.trace import load_trace


def test_graph_and_timeline(fx):
    t = load_trace(fx["sim_injector.bin"][1])
    g, tl = reconstruct(t)
    assert "proc:200" in g.roots()
    assert "proc:50" in g.descendants("proc:200")
    assert any(e.relation == "injected" for e in g.edges)
    assert {"T1055", "T1071"} <= {x.technique for x in tl}
    assert g.to_mermaid().startswith("flowchart LR")


def test_ransom_mapping(fx):
    _, tl = reconstruct(load_trace(fx["sim_ransom.bin"][1]))
    techs = {x.technique for x in tl}
    assert {"T1490", "T1486", "T1547.001"} <= techs
