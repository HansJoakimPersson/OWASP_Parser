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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Comparator;
import java.util.Set;
import java.util.TreeSet;

public class Dependency {
    private static final Logger logger = LogManager.getLogger(Main.class);

    private final TreeSet<Vulnerability> vulnerabilities = new TreeSet<>(new comparator());
    private String dependencyName = "";
    private String description = "";
    private String project = "";
    private final Set<Vulnerability> vulnerabilities = new TreeSet<>();
    private String moduleName = "";

    public String getProject() {
        return project;
    }

    public void setProject(String project) {
        this.project = project;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    public Set<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public String getDependencyName() {
        return dependencyName;
    }

    public void setDependencyName(String dependencyName) {
        this.dependencyName = dependencyName;
    }

    public String getModuleName() {
        return this.moduleName;
    }

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    private class comparator implements Comparator<Vulnerability> {
        @Override
        public int compare(Vulnerability o1, Vulnerability o2) {

            if (o1.getCVSS3() != null && o2.getCVSS3() != null) {
                return o1.getCVSS3() < o2.getCVSS3() ? 1 : -1;
            } else if (o1.getCVSS2() != null && o2.getCVSS2() != null) {
                return o1.getCVSS2() < o2.getCVSS2() ? 1 : -1;
            }
            logger.error("Should never happen, and means something is wrong with the comparison");
            return 0;
        }
    }
}
