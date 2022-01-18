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

import java.util.Set;
import java.util.TreeSet;

public class Dependency {
    private String dependencyName = "";
    private String description = "";
    private String project = "";
    private Set<Vulnerability> vulnerabilities = new TreeSet<>();
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

    @Override
    public String toString() {
        return "Dependency{" +
                "name='" + dependencyName + '\'' +
                ", description='" + description + '\'' +
                ", vulnerabilities=" + vulnerabilities.toString() +
                '}';
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

    public void setModuleName(String moduleName) {
        this.moduleName = moduleName;
    }

    public String getModuleName() {
        return this.moduleName;
    }

}
