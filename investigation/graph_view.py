from __future__ import annotations

import math
from collections import defaultdict, deque

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGraphicsItem,
    QGraphicsObject,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)


# Maltego-inspired investigation canvas: dark workspace, semantic node styling,
# force-directed positioning, selectable entities, curved relationships, and a
# compact details inspector.  It deliberately uses only PyQt6.

BG = QColor("#0b0f14")
GRID = QColor("#151b23")
EDGE = QColor("#5b6675")
EDGE_HOVER = QColor("#b9c7d9")
TEXT = QColor("#eef3f8")
MUTED = QColor("#8d9aaa")
PANEL = QColor("#111821")
BORDER = QColor("#263241")

NODE_COLORS = {
    "finding": QColor("#e05263"),
    "event": QColor("#4f9cf9"),
    "user": QColor("#a78bfa"),
    "computer": QColor("#38bdf8"),
    "ip": QColor("#22c55e"),
    "domain": QColor("#14b8a6"),
    "hash": QColor("#f59e0b"),
    "mitre": QColor("#f97316"),
    "entity": QColor("#c084fc"),
    "evidence": QColor("#64748b"),
}

NODE_LABELS = {
    "finding": "FINDING",
    "event": "EVENT",
    "user": "USER",
    "computer": "COMPUTER",
    "ip": "IP",
    "domain": "DOMAIN",
    "hash": "HASH",
    "mitre": "MITRE ATT&CK",
    "entity": "ENTITY",
    "evidence": "EVIDENCE",
}


class GraphNodeItem(QGraphicsObject):
    clicked = pyqtSignal(object)
    hovered = pyqtSignal(object, bool)

    WIDTH = 178
    HEIGHT = 74

    def __init__(self, node: dict, parent=None):
        super().__init__(parent)
        self.node = node
        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self._hovered = False

    def boundingRect(self):
        return QRectF(-self.WIDTH / 2, -self.HEIGHT / 2, self.WIDTH, self.HEIGHT)

    def paint(self, painter: QPainter, option, widget=None):
        del option, widget
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.boundingRect()
        color = NODE_COLORS.get(self.node["type"], QColor("#64748b"))
        selected = self.isSelected()

        # Soft outer glow when selected/hovered.
        if selected or self._hovered:
            glow = QColor(color)
            glow.setAlpha(55 if selected else 32)
            painter.setPen(QPen(glow, 8))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawRoundedRect(rect.adjusted(2, 2, -2, -2), 12, 12)

        fill = QColor("#151d27")
        painter.setBrush(QBrush(fill))
        painter.setPen(QPen(color if selected else BORDER, 2 if selected else 1.4))
        painter.drawRoundedRect(rect, 12, 12)

        # Accent stripe.
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(color))
        painter.drawRoundedRect(QRectF(rect.left(), rect.top(), 5, rect.height()), 3, 3)

        # Type badge.
        painter.setBrush(QBrush(color))
        painter.drawEllipse(QRectF(-78, -22, 22, 22))
        painter.setPen(QPen(QColor("#0b0f14"), 1))
        font = QFont("Segoe UI", 8, QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(QRectF(-78, -22, 22, 22), Qt.AlignmentFlag.AlignCenter, self._glyph())

        painter.setPen(TEXT)
        painter.setFont(QFont("Segoe UI", 8, QFont.Weight.Bold))
        painter.drawText(QRectF(-50, -25, 112, 18), Qt.AlignmentFlag.AlignLeft, NODE_LABELS.get(self.node["type"], self.node["type"].upper()))

        painter.setPen(QColor("#d9e2ec"))
        painter.setFont(QFont("Segoe UI", 9, QFont.Weight.DemiBold))
        value = self._display_value()
        painter.drawText(
            QRectF(-78, 2, 150, 20),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            self._elide(value, 24),
        )

        sub = self._subtitle()
        painter.setPen(MUTED)
        painter.setFont(QFont("Segoe UI", 7))
        painter.drawText(
            QRectF(-78, 23, 150, 14),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            self._elide(sub, 31),
        )

    def _glyph(self):
        return {
            "finding": "!",
            "event": "E",
            "user": "U",
            "computer": "C",
            "ip": "#",
            "domain": "D",
            "hash": "H",
            "mitre": "M",
            "entity": "N",
            "evidence": "F",
        }.get(self.node["type"], "?")

    def _display_value(self):
        attrs = self.node.get("attributes", {})
        node_type = self.node["type"]
        value = attrs.get("value")

        if node_type == "finding":
            return attrs.get("rule_id") or str(self.node["id"])
        if node_type == "event":
            return f"Event ID {attrs.get('windows_event_id', self.node['id'])}"
        if node_type == "mitre":
            return str(self.node["id"])
        if value:
            return str(value)
        return str(self.node["id"])

    def _subtitle(self):
        attrs = self.node.get("attributes", {})
        node_type = self.node["type"]
        if node_type == "finding":
            return str(attrs.get("severity", ""))
        if node_type == "event":
            record = attrs.get("record_id")
            return f"Record {record}" if record is not None else "Windows event"
        if node_type == "mitre":
            return str(attrs.get("name", "MITRE technique"))
        if node_type == "entity":
            return str(attrs.get("entity_type", "entity"))
        return NODE_LABELS.get(node_type, node_type)

    @staticmethod
    def _elide(value, max_chars):
        value = str(value or "")
        return value if len(value) <= max_chars else value[: max_chars - 1] + "…"

    def hoverEnterEvent(self, event):
        self._hovered = True
        self.hovered.emit(self.node, True)
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hovered = False
        self.hovered.emit(self.node, False)
        self.update()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.node)
        super().mousePressEvent(event)


class GraphEdgeItem(QGraphicsPathItem):
    def __init__(self, source: QPointF, target: QPointF, relation: str, parent=None):
        super().__init__(parent)
        self.relation = relation
        self._hovered = False
        self.setAcceptHoverEvents(True)
        self.setZValue(-10)

        path = QPainterPath()
        dx = target.x() - source.x()
        dy = target.y() - source.y()
        distance = max(1.0, math.hypot(dx, dy))
        curve = min(90.0, distance * 0.22)
        nx = -dy / distance
        ny = dx / distance
        control = QPointF(
            (source.x() + target.x()) / 2 + nx * curve,
            (source.y() + target.y()) / 2 + ny * curve,
        )
        path.moveTo(source)
        path.quadTo(control, target)
        self.setPath(path)

        self.setPen(QPen(EDGE, 1.35))
        self.setToolTip(relation)

        # Arrow head.
        angle = math.atan2(target.y() - control.y(), target.x() - control.x())
        arrow_size = 8.0
        p1 = target
        p2 = target - QPointF(math.cos(angle - math.pi / 6) * arrow_size, math.sin(angle - math.pi / 6) * arrow_size)
        p3 = target - QPointF(math.cos(angle + math.pi / 6) * arrow_size, math.sin(angle + math.pi / 6) * arrow_size)
        self.arrow = QPolygonF([p1, p2, p3])

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(EDGE_HOVER if self._hovered else EDGE, 2.2 if self._hovered else 1.35)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(self.path())
        painter.setBrush(QBrush(EDGE_HOVER if self._hovered else EDGE))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPolygon(self.arrow)

        if self._hovered and self.relation:
            pos = self.path().pointAtPercent(0.5)
            painter.setPen(QPen(QColor("#0b0f14"), 5))
            painter.setFont(QFont("Segoe UI", 8, QFont.Weight.DemiBold))
            painter.drawText(QRectF(pos.x() - 90, pos.y() - 14, 180, 28), Qt.AlignmentFlag.AlignCenter, self.relation)
            painter.setPen(TEXT)
            painter.drawText(QRectF(pos.x() - 90, pos.y() - 14, 180, 28), Qt.AlignmentFlag.AlignCenter, self.relation)

    def hoverEnterEvent(self, event):
        self._hovered = True
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hovered = False
        self.update()
        super().hoverLeaveEvent(event)


class InvestigationCanvas(QGraphicsView):
    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        self.setBackgroundBrush(QBrush(BG))
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._zoom = 0

    def wheelEvent(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        if factor > 1 and self._zoom >= 12:
            return
        if factor < 1 and self._zoom <= -10:
            return
        self.scale(factor, factor)
        self._zoom += 1 if factor > 1 else -1


class InvestigationGraphView(QWidget):
    def __init__(self, database, case_id, parent=None):
        super().__init__(parent)
        self.database = database
        self.case_id = case_id
        self._all_nodes = {}
        self._all_edges = []

        self.scene = QGraphicsScene(self)
        self.view = InvestigationCanvas(self.scene)

        self.finding_combo = QComboBox()
        self.finding_combo.currentIndexChanged.connect(self._finding_changed)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search nodes…")
        self.search.textChanged.connect(self._filter_nodes)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        self.fit_button = QPushButton("Fit")
        self.fit_button.clicked.connect(self.fit_graph)
        self.reset_button = QPushButton("Reset")
        self.reset_button.clicked.connect(self._draw_current_finding)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(10, 8, 10, 8)
        toolbar.addWidget(QLabel("Finding"))
        toolbar.addWidget(self.finding_combo, 2)
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.fit_button)
        toolbar.addWidget(self.reset_button)
        toolbar.addWidget(self.refresh_button)

        self.inspector = QLabel("Select a node to inspect it.")
        self.inspector.setWordWrap(True)
        self.inspector.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.inspector.setMinimumWidth(245)
        self.inspector.setStyleSheet(
            "QLabel { color: #dbe5ef; background: #111821; border: 1px solid #263241; "
            "border-radius: 8px; padding: 14px; }"
        )

        self.legend = QLabel(self._legend_text())
        self.legend.setStyleSheet("color: #8d9aaa; padding: 8px 10px;")

        side = QVBoxLayout()
        side.setContentsMargins(8, 8, 8, 8)
        side.addWidget(QLabel("INSPECTOR"))
        side.addWidget(self.inspector, 1)
        side.addWidget(self.legend)

        side_widget = QWidget()
        side_widget.setLayout(side)
        side_widget.setMaximumWidth(285)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.view)
        splitter.addWidget(side_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setSizes([1000, 260])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addLayout(toolbar)
        layout.addWidget(splitter, 1)

        self.refresh()

    def refresh(self):
        current = self.finding_combo.currentData()
        self.finding_combo.blockSignals(True)
        self.finding_combo.clear()
        findings = self.database.get_case_findings(self.case_id)
        for row in findings:
            finding_id, rule_id, title, severity = row[:4]
            self.finding_combo.addItem(f"#{finding_id}  {rule_id}  ·  {severity}  ·  {title}", finding_id)
        if current is not None:
            index = self.finding_combo.findData(current)
            if index >= 0:
                self.finding_combo.setCurrentIndex(index)
        self.finding_combo.blockSignals(False)
        self._draw_current_finding()

    def _finding_changed(self, index):
        if index >= 0:
            self._draw_current_finding()

    def _draw_current_finding(self):
        finding_id = self.finding_combo.currentData()
        self.scene.clear()
        self._all_nodes.clear()
        self._all_edges.clear()
        self.inspector.setText("Select a node to inspect it.")
        if finding_id is None:
            return
        graph = self.database.get_finding_graph_data(finding_id)
        self._draw_graph(graph)

    def _draw_graph(self, graph):
        nodes = self._dedupe_nodes(graph.get("nodes", []))
        edges = self._dedupe_edges(graph.get("edges", []))
        if not nodes:
            return

        self._all_nodes = {f"{n['type']}:{n['id']}": n for n in nodes}
        self._all_edges = edges
        positions = self._force_layout(nodes, edges)

        # Edges first.
        for edge in edges:
            source = positions.get(edge["source"])
            target = positions.get(edge["target"])
            if source is None or target is None:
                continue
            self.scene.addItem(GraphEdgeItem(source, target, edge.get("relation", "")))

        # Nodes above edges.
        for node in nodes:
            key = f"{node['type']}:{node['id']}"
            pos = positions.get(key)
            if pos is None:
                continue
            item = GraphNodeItem(node)
            item.setPos(pos)
            item.clicked.connect(self._node_clicked)
            self.scene.addItem(item)

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-120, -120, 120, 120))
        self.fit_graph()

    def _node_clicked(self, node):
        attrs = node.get("attributes", {})
        lines = [
            f"<b>{NODE_LABELS.get(node['type'], node['type'].upper())}</b>",
            f"<b>ID:</b> {node['id']}",
        ]
        for key, value in attrs.items():
            if value not in (None, ""):
                lines.append(f"<b>{key.replace('_', ' ').title()}:</b> {value}")
        self.inspector.setText("<br>".join(lines))

        # Select the clicked node and dim unrelated nodes slightly.
        for item in self.scene.items():
            if isinstance(item, GraphNodeItem):
                item.setSelected(item.node is node)

    def _filter_nodes(self, query):
        query = query.strip().lower()
        for item in self.scene.items():
            if not isinstance(item, GraphNodeItem):
                continue
            node = item.node
            haystack = " ".join(
                [str(node.get("type", "")), str(node.get("id", ""))]
                + [str(v) for v in node.get("attributes", {}).values()]
            ).lower()
            item.setOpacity(1.0 if not query or query in haystack else 0.16)

    def fit_graph(self):
        rect = self.scene.itemsBoundingRect().adjusted(-80, -80, 80, 80)
        if rect.isValid() and not rect.isEmpty():
            self.view.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)
            self.view._zoom = 0

    @staticmethod
    def _dedupe_nodes(nodes):
        result = {}
        for node in nodes:
            result[f"{node['type']}:{node['id']}"] = node
        return list(result.values())

    @staticmethod
    def _dedupe_edges(edges):
        result = []
        seen = set()
        for edge in edges:
            key = (edge.get("source"), edge.get("relation"), edge.get("target"))
            if key in seen:
                continue
            seen.add(key)
            result.append(edge)
        return result

    @staticmethod
    def _force_layout(nodes, edges):
        keys = [f"{n['type']}:{n['id']}" for n in nodes]
        node_map = {f"{n['type']}:{n['id']}": n for n in nodes}
        adjacency = defaultdict(set)
        for edge in edges:
            if edge["source"] in node_map and edge["target"] in node_map:
                adjacency[edge["source"]].add(edge["target"])
                adjacency[edge["target"]].add(edge["source"])

        # Place the finding at the center and spread other nodes by graph distance.
        root = next((k for k in keys if k.startswith("finding:")), keys[0])
        distance = {root: 0}
        queue = deque([root])
        while queue:
            current = queue.popleft()
            for nxt in adjacency[current]:
                if nxt not in distance:
                    distance[nxt] = distance[current] + 1
                    queue.append(nxt)

        groups = defaultdict(list)
        for key in keys:
            groups[distance.get(key, 4)].append(key)

        positions = {}
        positions[root] = QPointF(0, 0)
        for level in sorted(groups):
            if level == 0:
                continue
            group = groups[level]
            radius = 245 + (level - 1) * 180
            count = len(group)
            for i, key in enumerate(group):
                angle = (2 * math.pi * i / max(1, count)) - math.pi / 2
                positions[key] = QPointF(math.cos(angle) * radius, math.sin(angle) * radius)

        # Lightweight deterministic force relaxation.
        for _ in range(90):
            disp = {k: QPointF(0, 0) for k in keys}
            for i, a in enumerate(keys):
                for b in keys[i + 1:]:
                    delta = positions[a] - positions[b]
                    dist = max(35.0, math.hypot(delta.x(), delta.y()))
                    force = 18000.0 / (dist * dist)
                    ux, uy = delta.x() / dist, delta.y() / dist
                    disp[a] += QPointF(ux * force, uy * force)
                    disp[b] -= QPointF(ux * force, uy * force)

            for edge in edges:
                a, b = edge["source"], edge["target"]
                if a not in positions or b not in positions:
                    continue
                delta = positions[b] - positions[a]
                dist = max(1.0, math.hypot(delta.x(), delta.y()))
                desired = 260.0
                force = (dist - desired) * 0.012
                ux, uy = delta.x() / dist, delta.y() / dist
                disp[a] += QPointF(ux * force, uy * force)
                disp[b] -= QPointF(ux * force, uy * force)

            for key in keys:
                if key == root:
                    continue
                p = positions[key] + disp[key]
                positions[key] = QPointF(
                    max(-1800, min(1800, p.x())),
                    max(-1200, min(1200, p.y())),
                )

        return positions

    @staticmethod
    def _legend_text():
        return "  ".join(f"● {label}" for label in ["Finding", "Event", "User", "Computer", "IOC", "MITRE"])
