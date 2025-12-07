import pytest
import shutil
import logging
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import argparse

from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.core.cve_service import CVEService

@pytest.fixture
def project_tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp("project_tests", numbered=True)

@pytest.fixture
def project_test_env(project_tmp_path):
    project_path = project_tmp_path / "test_project"
    output_path = project_tmp_path / "output"
    project_path.mkdir()
    output_path.mkdir()
    
    # Create a dummy cve_definitions.yml for CVEService initialization
    cve_defs_path = project_path / "cve_definitions.yml"
    cve_defs_path.touch()

    def _run_generator():
        with patch('pytm.pytm.get_args') as mock_get_args:
            mock_get_args.return_value = argparse.Namespace(debug=False, sqldump=None, dfd=None, report=None, exclude=None, seq=None, list=None, colormap=None, describe=None, list_elements=None, json=None, levels=None, stale_days=None)
            
            # Initialize CVEService with the dummy file
            # Assuming project_root for CVEService is the parent of project_path
            project_root = project_path.parent
            cve_service = CVEService(project_root, cve_defs_path)

            severity_calculator = SeverityCalculator()
            mitre_mapping = MitreMapping()
            report_generator = ReportGenerator(severity_calculator, mitre_mapping, cve_service=cve_service)
            report_generator.generate_project_reports(project_path, output_path)

    return project_path, output_path, _run_generator

@patch('threat_analysis.generation.report_generator._validate_path_within_project')
def test_single_level_project(mock_validate, project_test_env):
    # Arrange
    project_path, output_path, _run_generator = project_test_env
    mock_validate.side_effect = lambda x, **kwargs: Path(x)
    def create_mock_svg(dot_code, output_file, format):
        svg_path = Path(output_file)
        with open(svg_path, "w") as f:
            f.write("<svg></svg>")
        return str(svg_path)
    with patch('threat_analysis.generation.diagram_generator.DiagramGenerator.generate_diagram_from_dot', side_effect=create_mock_svg) as mock_generate_diagram, patch('threat_analysis.generation.diagram_generator.DiagramGenerator.add_links_to_svg', return_value="""
<svg>
<g id="WebApp" class="node">
<title>WebApp</title>
<a xlink:href="sub_A/model_diagram.html">
<ellipse fill="none" stroke="black" cx="49" cy="-18" rx="49" ry="18"/>
<text text-anchor="middle" x="49" y="-14.3" font-family="Times,serif" font-size="14.00">WebApp</text>
</a>
</g>
</svg>
""") as mock_add_links:

        sub_project_path = project_path / "sub_A"
        sub_project_path.mkdir(parents=True)
        with open(project_path / "main.md", "w") as f:
            f.write("""## Servers
- **WebApp**: submodel=./sub_A/model.md""")
        with open(sub_project_path / "model.md", "w") as f:
            f.write("""## Servers
- **WebServer**:""")

        # Act
        _run_generator()

        # Assert
        main_html = output_path / "main_diagram.html"
        sub_html = output_path / "sub_A" / "model_diagram.html"

        # The paths in the new implementation are different
        main_html_new = output_path / "main_diagram.html"
        sub_html_new = output_path / "sub_A" / "model_diagram.html"

        assert main_html_new.exists()
        assert sub_html_new.exists()

        main_content = main_html_new.read_text()
        assert 'xlink:href="sub_A/model_diagram.html"' in main_content

        sub_content = sub_html_new.read_text()
        assert 'href="../main_diagram.html"' in sub_content
        assert '<a href="../main_diagram.html">test_project</a>' in sub_content
        assert '<a href="model_diagram.html">sub_A</a>' in sub_content

@patch('threat_analysis.generation.diagram_generator.DiagramGenerator.add_links_to_svg')
@patch('threat_analysis.generation.diagram_generator.DiagramGenerator.generate_diagram_from_dot')
@patch('threat_analysis.generation.report_generator._validate_path_within_project')
def test_nested_project_and_dataflows(mock_validate, mock_generate_diagram, mock_add_links, project_test_env):
    # Arrange
    project_path, output_path, _run_generator = project_test_env
    mock_validate.side_effect = lambda x, **kwargs: Path(x)
    def create_mock_svg(dot_code, output_file, format):
        svg_path = Path(output_file)
        with open(svg_path, "w") as f:
            f.write("<svg></svg>")
        return str(svg_path)
    mock_generate_diagram.side_effect = create_mock_svg
    mock_add_links.return_value = """
<svg>
<g id="ProductDB" class="node">
<title>ProductDB</title>
<a xlink:href="database/model_diagram.html">
<ellipse fill="none" stroke="black" cx="49" cy="-90" rx="49" ry="18"/>
<text text-anchor="middle" x="49" y="-86.3" font-family="Times,serif" font-size="14.00">ProductDB</text>
</a>
</g>
</svg>
"""
    frontend_path = project_path / "frontend"
    backend_path = project_path / "backend"
    db_path = backend_path / "database"
    db_path.mkdir(parents=True)
    frontend_path.mkdir()

    with open(project_path / "main.md", "w") as f:
        f.write("""
## Servers
- **WebApp**: submodel=./frontend/model.md
- **Backend**: submodel=./backend/model.md
## Dataflows
- **WebToBackend**: from=WebApp, to=Backend, protocol=TCP
            """)
    with open(frontend_path / "model.md", "w") as f:
        f.write("""## Servers
- **WebServer**:""")
    with open(backend_path / "model.md", "w") as f:
        f.write("""## Servers
- **APIGateway**:
- **ProductDB**: submodel=./database/model.md""")
    with open(db_path / "model.md", "w") as f:
        f.write("""## Servers
- **PrimaryDB**:""")

    # Act
    _run_generator()

    # Assert
    backend_html = output_path / "backend" / "model_diagram.html"
    db_html = output_path / "backend" / "database" / "model_diagram.html"
    assert backend_html.exists()
    assert db_html.exists()

    backend_content = backend_html.read_text()
    assert 'xlink:href="database/model_diagram.html"' in backend_content

    db_content = db_html.read_text()
    assert 'href="../model_diagram.html"' in db_content
    assert '<a href="../../main_diagram.html">test_project</a>' in db_content
    assert '<a href="../model_diagram.html">backend</a>' in db_content
    assert '<a href="model_diagram.html">database</a>' in db_content

@patch('threat_analysis.generation.diagram_generator.DiagramGenerator.add_links_to_svg')
@patch('threat_analysis.generation.diagram_generator.DiagramGenerator.generate_diagram_from_dot')
def test_project_with_protocol_styles(mock_generate_diagram, mock_add_links, project_test_env):
    # Arrange
    project_path, output_path, _run_generator = project_test_env
    def create_mock_svg(dot_code, output_file, format):
        svg_path = Path(output_file)
        with open(svg_path, "w") as f:
            f.write("<svg></svg>")
        return str(svg_path)
    mock_generate_diagram.side_effect = create_mock_svg
    mock_add_links.return_value = "<svg></svg>"
    with open(project_path / "main.md", "w") as f:
        f.write("""
## Servers
- **ServerA**:
- **ServerB**:
## Dataflows
- **AToB**: from=ServerA, to=ServerB, protocol=HTTP
## Protocol Styles
- **HTTP**: color=red
            """)

    # Act
    _run_generator()

    # Assert
    main_html = output_path / "main_diagram.html"
    assert main_html.exists()
    main_content = main_html.read_text()
    assert "Protocoles:" in main_content
    assert "HTTP" in main_content
    assert "red" in main_content

