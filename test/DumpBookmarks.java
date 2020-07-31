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
// This script will replace all comments with values matching the given user
// search value with the given user replacement value.
//@category Update
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.Iterator;

public class DumpBookmarks extends GhidraScript {

    public void run() throws Exception {
        Program prog = currentProgram;
        Iterator<Bookmark> bookmarkIter =
            prog.getBookmarkManager().getBookmarksIterator("Error");
        int count = 0;
        while (bookmarkIter.hasNext()) {
            bookmarkIter.next();
            count++;
        }
        Msg.info(this, "STATUS: " + prog.getName() + ": " + count +
                           " error bookmarks.");
        return;
    }
}
