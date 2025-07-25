/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.framework.model;

import java.io.IOException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.options.SaveState;

/**
 * 
 * Interface to define methods to manage data and tools for users working on a
 * particular effort. Project represents the container object for users, data,
 * and tools to work together.
 * 
 */
public interface Project extends AutoCloseable, Iterable<DomainFile> {

	/**
	 * {@return the name of this project}
	 */
	public String getName();

	/**
	 * {@return the project locator for this project}
	 */
	public ProjectLocator getProjectLocator();

	/**
	 * {@return the project manager of this project}
	 */
	public ProjectManager getProjectManager();

	/**
	 * {@return the tool manager for this project}
	 */
	public ToolManager getToolManager();

	/**
	 * {@return the tool services for this project}
	 */
	public ToolServices getToolServices();

	/**
	 * {@return whether the project configuration has changed}
	 */
	public boolean hasChanged();

	/**
	 * {@return whether this project instance has been closed}
	 */
	public boolean isClosed();

	/**
	 * {@return the local tool chest for the user logged in}
	 */
	public ToolChest getLocalToolChest();

	/**
	 * Get the repository that this project is associated with.
	 * @return null if the project is not associated with a remote
	 * repository
	 */
	public RepositoryAdapter getRepository();

	/** 
	 * Add the given project URL to this project's list project views.
	 * The project view allows users to look at data files from another
	 * project.  If the URL corresponds to this project its ProjectData will be returned.
	 * @param projectURL identifier for the project view (ghidra protocol only).
	 * @param visible true if project may be made visible or false if hidden.  Hidden viewed
	 * projects are used when only life-cycle management is required (e.g., close view project 
	 * when this project is closed).
	 * @return project data for this view
	 * @throws IOException if this project is closed, an invalid URL is specified, or failed to 
	 * open/connect to project/repository.
	 */
	public ProjectData addProjectView(URL projectURL, boolean visible) throws IOException;

	/**
	 * Remove the project view from this project.
	 * @param projectURL identifier for the project 
	 */
	public void removeProjectView(URL projectURL);

	/**
	 * {@return the list of visible project views in this project}
	 */
	public ProjectLocator[] getProjectViews();

	/**
	 * Close the project.
	 */
	@Override
	public void close();

	/**
	 * Save the project and the list of project views.
	 */
	public void save();

	/**
	 * Saves any tools that are associated with the opened project when the project is closed. 
	 * 
	 * @return True if the save was not cancelled.
	 */
	public boolean saveSessionTools();

	/**
	 *  Restore this project's state.
	 */
	public void restore();

	/**
	* Save the given tool template as part of the project.
	* @param tag ID or name for the tool template
	* @param template template to save
	*/
	public void saveToolTemplate(String tag, ToolTemplate template);

	/**
	 * Get the tool template with the given tag.
	 * @param tag ID or name for the tool template to get
	 * @return tool template
	 */
	public ToolTemplate getToolTemplate(String tag);

	/**
	 * Allows the user to store data related to the project.
	 * See {@link #getSaveableData(String)} for future retieval of data.
	 * @param key a value used to store and lookup saved data
	 * @param saveState a container of data that will be written out when persisted
	 */
	public void setSaveableData(String key, SaveState saveState);

	/**
	 * {@return the user data previously stored to the project}
	 * See {@link #setSaveableData(String, SaveState)}.
	 * @param key a value used to store and lookup saved data
	 */
	public SaveState getSaveableData(String key);

	/**
	 * Get list of domain files that are open.
	 * @return the files; empty if no files
	 */
	public List<DomainFile> getOpenData();

	/**
	 * {@return the root domain data folder in the project}
	 */
	public ProjectData getProjectData();

	/**
	 * Returns the Project Data for the given Project locator.  The Project locator must
	 * be either the current active project or an currently open project view.
	 * The returned view may not be visible.
	 * @param projectLocator project locator object used to open project
	 * @return requested project data
	 */
	public ProjectData getProjectData(ProjectLocator projectLocator);

	/** 
	 * Returns the Project Data for the given Project URL.  The Project URL must
	 * be either the current active project or a currently open project view.
	 * The returned view may not be visible.
	 * @param projectURL identifier for the project view (ghidra protocol only).
	 * @return project data for this view or null
	 */
	public ProjectData getProjectData(URL projectURL);

	/**
	 * Get the project data for visible viewed projects that are
	 * managed by this project.
	 * @return zero length array if there are no visible viewed projects open
	 */
	public ProjectData[] getViewedProjectData();

	/**
	 * Releases all DomainObjects used by the given consumer
	 * @param consumer object no longer using any DomainObjects.
	 */
	public void releaseFiles(Object consumer);

	/**
	 * Add a listener to be notified when a visible project view is added or removed.
	 * @param listener project view listener
	 */
	public void addProjectViewListener(ProjectViewListener listener);

	/**
	 * Remove a project view listener previously added.
	 * @param listener project view listener
	 */
	public void removeProjectViewListener(ProjectViewListener listener);

	/**
	 * Return a {@link DomainFile} iterator over all non-link files within this project's data store.
	 * If links should be followed use an appropropriate static method from {@link ProjectDataUtils}.
	 * @return domain file iterator
	 */
	@Override
	public default Iterator<DomainFile> iterator() {
		return getProjectData().iterator();
	}

}
