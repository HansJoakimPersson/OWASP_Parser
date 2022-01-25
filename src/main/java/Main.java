/*
 *  Copyright (c) 2022.  Joakim Persson (hans.joakim.persson@gmail.com)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.poi.ss.util.AreaReference;
import org.apache.poi.ss.util.CellReference;
import org.apache.poi.xssf.usermodel.*;
import org.htmlcleaner.CleanerProperties;
import org.htmlcleaner.HtmlCleaner;
import org.htmlcleaner.TagNode;
import org.htmlcleaner.XPatherException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class Main {

    private static final Logger logger = LogManager.getLogger(Main.class);
    private static final HtmlCleaner htmlCleaner = new HtmlCleaner(new CleanerProperties());

    public static void main(String[] args) {
        logger.info("Working directory is " + System.getProperty("user.dir"));

        List<Dependency> dependencyList = new ArrayList<>();

        // Try to read and parse all files in working directory that have html extension
        try (Stream<Path> paths = Files.walk(Paths.get(System.getProperty("user.dir")))) {
            paths
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith("html"))
                    .forEach(p -> dependencyList.addAll(parse(p)));
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            if (!(dependencyList.size() == 0)) {
                CreateXLSX(dependencyList);
            } else {
                logger.info("No dependencies found");
                System.exit(0);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static List<Dependency> parse(Path p) {
        logger.info("Parsing: " + p);
        List<Dependency> dependencyList = new ArrayList<>();

        try {
            TagNode tn = htmlCleaner.clean(Files.readString(p));
            Object[] header = tn.evaluateXPath("//h3[@class='subsectionheader standardsubsection']");
            Object[] content = tn.evaluateXPath("//div[@class='subsectioncontent']");

            try {
                String project = StringEscapeUtils.unescapeHtml4(((TagNode) tn.evaluateXPath("//div/h2")[0]).getText().toString()).split(":")[1].trim();
                if (header != null && content != null && header.length > 0 && content.length > 0) {
                    for (int i = 0; i < header.length; i++) {

                        Dependency dependency = new Dependency();

                        dependency.setProject(project);

                        String[] split = ((TagNode) header[i]).getText().toString()
                                .replaceAll(" \\(shaded: .*?\\)", "").split(":");

                        if (split.length > 1) {
                            dependency.setModuleName(String.join(": ", Arrays.copyOfRange(split, 0, split.length - 1)).trim());
                            dependency.setDependencyName(split[split.length - 1].trim());
                        } else {
                            dependency.setDependencyName(split[0].trim());
                        }


                        logger.debug("Found dependency: " + dependency.getProject() + ", " + dependency.getDependencyName());

                        // Ugliest code ever written, since the p elements used for cvss i non-hierarchical we have to split
                        // based on content, and Insha'Allah everything lines up
                        List<TagNode> nodes = (((TagNode) ((TagNode) content[i]).evaluateXPath("/div/p/b/a/../../..")[0]).getAllChildren()).stream().map(o -> (TagNode) o).collect(Collectors.toList());

                        List<List<TagNode>> cvss = new ArrayList<>();
                        List<TagNode> temp = new ArrayList<>();

                        for (TagNode node : nodes) {

                            if (node.getAllChildren().size() > 2 && node.getAllChildren().get(2).toString().contains("button")) {
                                if (!temp.isEmpty()) {
                                    cvss.add(temp);
                                }
                                temp = new ArrayList<>();
                            }
                            temp.add(node);
                        }
                        cvss.add(temp);

                        for (int j = 0; j < ((TagNode) content[i]).evaluateXPath("/div/p/b/a").length; j++) {
                            Vulnerability vulnerability = new Vulnerability();

                            vulnerability.setCVE(((TagNode) ((TagNode) content[i]).evaluateXPath("/div/p/b/a")[j]).getText());
                            logger.debug("Added CVE: " + vulnerability.getCVE());

                            vulnerability.setDescription(((TagNode) ((TagNode) content[i]).evaluateXPath("/div/pre")[j]).getText());
                            logger.debug("Added description: " + vulnerability.getDescription());

                            List<TagNode> list = cvss.get(j);
                            if (list != null) {
                                for (TagNode o : list) {
                                    if (o.getName().contains("ul") && o.getAllChildren().size() == 2) {
                                        if (((TagNode) o.getAllChildren().get(1)).getText().toString().contains("Vector: CVSS:3")) {
                                            split = ((TagNode) o.getAllChildren().get(0)).getText().toString().split("\\(");
                                            if (split.length == 2) {
                                                vulnerability.setCVSS3(Double.parseDouble(split[1].replace(")", "")));
                                                logger.debug("Added CVSS3: " + vulnerability.getCVSS3());
                                            }

                                            split = ((TagNode) o.getAllChildren().get(1)).getText().toString().split("CVSS:3.*?/");
                                            if (split.length == 2) {
                                                vulnerability.setAttackVector3(split[1]);
                                                logger.debug("Added attackvector: " + vulnerability.getAttackVector3());
                                            }

                                        } else if (((TagNode) o.getAllChildren().get(1)).getText().toString().contains("Vector:")) {
                                            split = ((TagNode) o.getAllChildren().get(0)).getText().toString().split("\\(");
                                            if (split.length == 2) {
                                                vulnerability.setCVSS2(Double.parseDouble(split[1].replace(")", "")));
                                                logger.debug("Added CVSS2: " + vulnerability.getCVSS2());
                                            }
                                            split = ((TagNode) o.getAllChildren().get(1)).getText().toString().split("Vector: /");
                                            if (split.length == 2) {
                                                vulnerability.setAttackVector2(split[1]);
                                                logger.debug("Added attackvector: " + vulnerability.getAttackVector2());
                                            }
                                        }
                                    }
                                }
                            }

                            dependency.addVulnerability(vulnerability);
                        }
                        dependencyList.add(dependency);
                    }
                }

            } catch (ArrayIndexOutOfBoundsException e) {
                System.err.println(e.getMessage());
            }

        } catch (IOException e) {
            System.err.println(e.getMessage());
        } catch (XPatherException e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
        }
        logger.info("Found " + dependencyList.stream().mapToInt(dependency -> dependency.getVulnerabilities()
                .size()).sum() + " vulnerabilities in " + dependencyList.size() + " packages");
        return dependencyList;
    }

    private static void CreateXLSX(List<Dependency> dependencyList) throws IOException {
        try (XSSFWorkbook workbook = new XSSFWorkbook()) {
            XSSFSheet sheet1 = workbook.createSheet("Vulnerabilities");

            // Set which area the table should be placed in
            AreaReference reference = workbook.getCreationHelper().createAreaReference(
                    new CellReference(0, 0), new CellReference(dependencyList.stream().mapToInt(dependency -> dependency.getVulnerabilities()
                            .size()).sum(), 10));

            // Create
            XSSFTable vulnTable = sheet1.createTable(reference);
            vulnTable.setName("Vulnerabilities");
            vulnTable.setDisplayName("Vulnerabilities");

            // For now, create the initial style in a low-level way
            vulnTable.getCTTable().addNewTableStyleInfo();
            vulnTable.getCTTable().getTableStyleInfo().setName("TableStyleMedium2");
            vulnTable.getCTTable().addNewAutoFilter();

            // Style the table
            XSSFTableStyleInfo style = (XSSFTableStyleInfo) vulnTable.getStyle();
            style.setName("TableStyleMedium2");
            style.setShowColumnStripes(false);
            style.setShowRowStripes(true);
            style.setFirstColumn(false);
            style.setLastColumn(false);

            //sheet1.setAutoFilter(CellRangeAddress.valueOf("A1:J1"));

            XSSFRow row = sheet1.createRow(0);
            row.createCell(0).setCellValue("Project");
            row.createCell(1).setCellValue("Module");
            row.createCell(2).setCellValue("Dependency");
            row.createCell(3).setCellValue("CVE");
            row.createCell(4).setCellValue("Base Score (CVSS2)");
            row.createCell(5).setCellValue("Severity (CVSS2");
            row.createCell(6).setCellValue("Attack Vector (CVSS2)");
            row.createCell(7).setCellValue("Base Score (CVSS3)");
            row.createCell(8).setCellValue("Severity (CVSS3)");
            row.createCell(9).setCellValue("Attack Vector (CVSS3)");
            row.createCell(10).setCellValue("Description");

            // Set the values for the table
            int rowNr = 1;
            for (Dependency dependency : dependencyList) {

                for (Vulnerability vulnerability : dependency.getVulnerabilities()) {

                    row = sheet1.createRow(rowNr);
                    row.createCell(0).setCellValue(dependency.getProject());
                    row.createCell(1).setCellValue(dependency.getModuleName());
                    row.createCell(2).setCellValue(dependency.getDependencyName());
                    row.createCell(3).setCellValue(vulnerability.getCVE());
                    row.createCell(4).setCellValue(vulnerability.getCVSS2());
                    row.createCell(5).setCellValue(toSeverity(vulnerability.getCVSS2()));
                    row.createCell(6).setCellValue(vulnerability.getAttackVector2());
                    if (vulnerability.getCVSS3() != null) {
                        row.createCell(7).setCellValue(vulnerability.getCVSS3());
                    }
                    row.createCell(8).setCellValue(toSeverity(vulnerability.getCVSS3()));
                    row.createCell(9).setCellValue(vulnerability.getAttackVector3());
                    row.createCell(10).setCellValue(vulnerability.getDescription());
                    rowNr++;
                }
            }

            try (FileOutputStream fileOut = new FileOutputStream("OWASP Dependency-Check Report.xlsx")) {
                workbook.write(fileOut);
            }
        }
    }

    private static String toSeverity(Double cvss) {
        if (cvss != null) {
            if (cvss >= 9.0) {
                return "Critical";
            } else if (cvss >= 7.0) {
                return "High";
            } else if (cvss >= 4) {
                return "Medium";
            } else if (cvss >= 0.1) {
                return "Low";
            }
            return "None";
        }
        return "";
    }
}
